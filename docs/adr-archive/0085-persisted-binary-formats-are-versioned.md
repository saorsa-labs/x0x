# ADR 0085: Persisted Binary Formats Are Versioned, Read Every Released Layout, and Fail Closed on Downgrade

- **Status:** Accepted
- **Accepted:** 2026-09-28 by David Irvine (charter decision D01 companion to #1046: versioned snapshot magic, frozen decoders for released layouts, fail-closed downgrade accepted; accepted after Codex cross-model review round 2 APPROVED with no open findings; status change applied by Claude at his instruction)
- **Date:** 2026-09-28
- **Decision owners:** David Irvine (decision), Claude x0x-32 (drafting)
- **Reviewers:** OMP (cross-model review); David Irvine (acceptance)
- **Supersedes:** none
- **Superseded by:** none
- **Vision requirement:** R6 (agents collaborate across machines: KV, group
  and Home stores must survive an upgrade). It also serves the proposed R12
  (D20: agents upgrade and roll back x0x safely), which needs upgrades that
  never lose state and downgrades that never corrupt it.
- **Related:** #1046 (fix and tests), charter decision D01 and release-gate
  row 4 (`.planning/x0x-charter-2026-09-28.md`),
  `.planning/mixed-version-matrix-0.46.md` (C1, §G),
  `docs/design/persisted-format-compat.md` (lands with #1046), ADR-0015,
  ADR-0023

## Context

- **How KV snapshots are stored.** Each persistent KV store (personal,
  directory, group and Home) is snapshotted to
  `<data_dir>/kv-stores/<id>.bin` as `X0XKVS1\0 || bincode(KvStore) || u64
  seq_counter`.
- **Why bincode 1.x is fragile here.** It is positional and not
  self-describing:
  - `#[serde(default)]` does nothing for a field that is missing from an old
    file.
  - A field added to a struct that is followed by more data reads the next
    bytes as its own value.
- **What broke.** Commits 97813fa and 8bd7c64 (on main since 2026-09-14)
  appended `KvStore.last_history_endorser`. In a v0.45.0 file that field
  swallows the start of `seq_counter`, so **every v0.45.0 snapshot fails with
  `UnexpectedEof`**. After an upgrade, every KV, group and Home store refuses
  to open ("refusing to start with amnesia").
- **Why nothing caught it:**
  - No test loaded a file written by a released binary.
  - The `X0XKVS1` magic carried no body version, so the decoder could not
    tell the old layout from the new one.
- **The audit.** The #1046 audit of every persisted format changed since
  v0.45.0 found this was the only live break. It also found latent hazards of
  the same class:
  - `TaskList` sits mid-stream;
  - the share-grant files have magic numbers but no body version;
  - the key-move records sit mid-stream;
  - the exec and connect ACL TOML use `deny_unknown_fields`, so a v0.45.0
    daemon refuses to start on a file that uses the new `principal` field.

## Decision Drivers

- An upgrade must never lose or strand persisted state.
- A downgrade must never corrupt or delete state that a newer version wrote.
  Unavailable-but-intact is acceptable (D01).
- The rules must be checkable in CI, not left to reviewer memory.
- This has to be a fix, not a storage redesign (fixes-only moratorium).

## Considered Options

1. **Versioned magic plus a frozen decoder for every released layout**
   (#1046). Write `X0XKVS2` with the counter first, and read `X0XKVS1`
   through a frozen v0.45.0 shape.
2. **Revert `last_history_endorser`** out of the persisted struct. This fixes
   the one break but leaves the class open, and loses the field's durability.
3. **Move persisted state to a self-describing encoding** (JSON, CBOR,
   postcard with explicit versions). That is the right long-term direction,
   but it is a storage migration and out of scope before v0.46.0.
4. **Make the downgrade transparent** by writing v1 until every peer runs
   0.46. That can't be expressed as a v1 file (the layout cannot carry the new
   field) and gives no benefit, because snapshots are local.

## Decision

We take option 1 and adopt it as the rule for **every** persisted
binary-encoded format:

1. **A version is part of the format.**
   - Every positional (bincode or postcard) persisted file starts with a magic
     that names its body layout.
   - Any change to the encoded shape of a persisted type gets a new magic
     (`…2`, `…3`).
   - "Append a tolerant field" is allowed only when the field is at the true
     end of the whole encoded stream. It must be documented as such at the
     type.
2. **Every released layout stays readable.**
   - A new version keeps a decoder for each layout that a tagged release
     wrote. It decodes through a **frozen copy** of that release's serde
     shape (for KV: `KvStoreV1SnapshotShape`), never through the live type.
   - Bodies must be consumed exactly, so trailing bytes are an error.
   - A fallback layout is allowed only when at most one candidate layout can
     consume a given body exactly.
3. **Files are rewritten lazily.** An old-layout file is rewritten in the new
   layout on its next ordinary persist. It is never migrated eagerly at
   startup.
4. **Unknown formats fail closed.**
   - An unknown magic, or a body that doesn't decode, is refused with an
     explicit error, and the file is left untouched.
   - The software never auto-deletes, truncates or overwrites a file it
     cannot read.
5. **The downgrade contract is the one D01 accepts.**
   - An older binary that meets a newer magic refuses that one store: it logs
     it, skips it, and keeps the manifest entry, so a later restart retries.
   - It leaves the file byte-identical. Upgrading again restores the store in
     full.
   - Release notes say this for every format whose magic changed.
6. **Proof comes from real release artifacts.**
   - Any PR that changes a persisted type must add or keep a fixture
     generated by the **released** binary's own encoder, with its provenance
     and sha256 recorded (for KV: `tests/fixtures/kv_snapshot_v0_45_0.bin`),
     and a test that loads it.
   - Each release gate includes a row that starts the candidate on a real
     `data_dir` from the previous release, and then checks the downgrade
     (charter §8, row 4).
7. **Text configs:** a new optional field in a `deny_unknown_fields` TOML or
   JSON file is a downgrade break. The release notes must list it with the
   workaround (for the ACLs: add `principal` entries through the API overlay,
   not the TOML) until those files get a version key.

## Consequences

### Positive

- The v0.46.0 upgrade keeps every v0.45.0 store (#1046 closes C1).
- This class of break becomes visible in review and CI (the fixture load
  fails), not in the field.
- Downgrade behaviour is defined and safe: data stays intact, and some
  stores are unavailable on the older version.

### Negative / Trade-offs

- **A downgrade to 0.45 cannot open any store that 0.46 has written to.**
  Users who downgrade lose access to those stores until they upgrade again.
  This is accepted (D01).
- Frozen shape copies accumulate, one per released layout, in each affected
  module. They can be retired only by a later ADR that sets a minimum
  upgradable version.
- The latent hazards (`TaskList`, the share-grant files, key-move records,
  and the ACL `deny_unknown_fields`) are not fixed by this ADR. Each is fixed
  the first time its type changes, by following rules 1 and 6.

### Neutral / Operational

- Option 3 (self-describing storage) stays open for after v0.46. This ADR
  doesn't block it: a new format simply gets a new magic.

## Validation

- These #1046 tests are in `src/kv/sync.rs`:
  - `v045_snapshot_fixture_loads` is red on the unfixed tree
    (`Serialization(Io(Kind(UnexpectedEof)))`, CI run 36401846399) and green
    with the fix;
  - `v045_snapshot_resaves_as_v2_and_round_trips`;
  - `v2_snapshot_round_trips_new_fields`;
  - `prerelease_v1_current_shape_snapshot_still_loads`;
  - `snapshot_roundtrip_missing_and_corrupt`, which covers the fail-closed
    cases.
- A v0.45.0 `load_snapshot` was run against a v2 file: it refused the file
  and left it byte-identical.
- **Real release `data_dir`, loader level** (on main since #1046, e7ba342):
  - `tests/fixtures/v045_data_dir/` was written by the v0.45.0 release binary.
    Its `PROVENANCE.md` records the binary sha256, the steps and a hash for
    every file.
  - `tests/v045_data_dir_fixture.rs` decodes every KV-store and task-list
    snapshot in that directory through the daemon's own loaders
    (`kv::sync::load_snapshot`, `TaskListStorage::load_task_list_opt`) and
    checks the values written through the v0.45.0 API.
  - On afacc56 (before #1046), `every_v045_kv_store_snapshot_loads` is
    **red**: `kv-stores/31fc…54ec.bin must load: … unexpected end of file`
    (`PROVENANCE.md` L38–43). With #1046 it is **green**, and the task-list
    control passes on both.
  - These are **loader tests**. They start no daemon, open no store through
    the API, and do not exercise downgrade.
- **Daemon upgrade and downgrade** (the release gate, a separate check):
  v0.46.0 gate row 4 copies the same `data_dir` to a host, then:
  - upgrades in place, checking that the stores open through the running
    daemon;
  - downgrades to v0.45.0, checking that stores 0.46 wrote to are refused
    with the files left byte-identical;
  - upgrades again, checking that the stores come back.

## Notes for AI-assisted work

- Before adding a field to anything serialized with bincode or postcard and
  written to disk, find the file's magic. If the field is not at the true end
  of the stream, add a new magic and a frozen decoder for the old one.
- Never "fix" an unreadable file by deleting it or writing over it.
- A new fixture must come from the released binary's encoder, not from the
  current code.
