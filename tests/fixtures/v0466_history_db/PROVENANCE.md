# v0.46.6 `history.db` fixture: provenance

`history.db` here is a real schema-4 durable-history database written by the
**released v0.46.6 `x0xd`**. It is the "released schema-4 fixture" of ADR 0116
Validation row "Storage and downgrade" (slice F). The inert tests in
`src/history/fixture_v0466_tests.rs` use it; `downgrade_proof.py` uses it for
the scripted older-binary run.

## How it was made (2026-10-10)

1. **Binary (approved by David, D239).** This is the `v0.46.6` GitHub
   release asset `x0x-macos-arm64.tar.gz`, downloaded for this fixture only.
   - Archive sha256:
     `03b16fc190a9583c76e940b736e5c0a8e315b158dd0e0b6ae6d54507f7db0faf`. It
     matches the release's `.sha256` file and the `archive_sha256` in its
     signed `release-manifest.json`. That manifest and its ML-DSA signature
     are byte-identical to the ones verified at release.
   - Extracted binaries. Both match the archive's `build-provenance.json`,
     whose `source_head` is `a36fc495ad230331570a2c55d37f4b2295c51d1e`, tag
     `v0.46.6`:
     - `x0xd` sha256
       `1357f84994ac195c31293f2e880923c354b07866f878cabd1dec7f6c3650875f`.
     - `x0x` sha256
       `48cc8b5ffee9f1a4ab87961e5a2f2f50afcf94bb78980a727d121933aa9ad441`.
   - `x0xd --version`, run under the sandbox below, prints `x0xd 0.46.6`.
2. **Isolation.**
   - The daemon ran only under `sandbox-exec` with this profile, which denies
     every non-loopback outbound connection:
     ```
     (version 1)
     (allow default)
     (deny network-outbound)
     (allow network-outbound (remote ip "localhost:*"))
     (allow network-outbound (remote unix-socket))
     ```
   - The environment was only `PATH=/usr/bin:/bin` and `HOME=<scratch>/home`,
     so `~/.x0x` was never touched.
   - Config, written by the script:
     - `bind_address = "127.0.0.1:19587"`, `api_address = "127.0.0.1:19707"`.
     - `bootstrap_peers = []`; mDNS, port mapping and rendezvous off.
     - `data_dir` and `identity_dir` inside the scratch dir.
     - `[history] enabled = true`,
       `record_topics = ["fixture.chat", "fixture.notes"]`.
     - `[update] enabled = false`.
   - Flags: `--no-hard-coded-bootstrap --disable-peer-cache --skip-update-check`.
3. **Throwaway identity.** The daemon generated its machine and agent keys on
   first start. No user key was made. **These keys are test-only, they never
   touched any network, and they are not committed:** only `history.db` is.
4. **Command.** Run from the repository root:
   ```
   python3 tests/fixtures/v0466_history_db/make_fixture.py \
     --x0xd <scratch>/bin/x0x-macos-arm64/x0xd \
     --sandbox .planning/team-2026-10-05/loopback-only.sb \
     --work <scratch>/final/work \
     --out tests/fixtures/v0466_history_db/history.db \
     --summary tests/fixtures/v0466_history_db/rows.json
   ```
   The script, `make_fixture.py`, starts the daemon, seeds rows through the
   daemon's own REST API, waits until `/history/stats` is stable, and lists
   every row (`rows.json`). It then stops the daemon with SIGTERM (exit code
   0), checks that no `-wal`/`-shm` content is left, and copies `history.db`.
5. **Rows written through the v0.46.6 REST API** (15: 13 Durable, 2
   Replaceable):

   | Scope | Rows | How |
   |---|---|---|
   | `topic:fixture.chat` | 3 Durable, text | `POST /subscribe` to the daemon's own topic, then `POST /publish`. Texts: "chat one: the quick brown fox", "chat two: lazy dog jumps", "chat three: retained topic text" |
   | `topic:fixture.notes` | 2 Durable, text | the same |
   | `dm:<own agent>` | 3 Durable, outbound text | `POST /direct/send` to the daemon's own agent id (the loopback path) |
   | `dm:<own agent>` | 1 Replaceable, `agent-card:…` | `GET /agent/card`, then `POST /agent/card/import` |
   | `group:<public group>` | 3 Durable, text, signed artifact, canonical projection | `POST /groups` (`public_open`), then `POST /groups/:id/send` |
   | `group:<public group>` | 1 Replaceable, `group-card:…` | `GET /groups/cards/:id`, then `POST /groups/cards/import` |
   | `group:<secure group>` | 2 Durable, MLS plaintext, no artifact | `POST /groups` (default `private_secure`), then `POST /groups/:id/secure/encrypt` |

   - Every text row is FTS-indexed; the two cards are JSON, so they are not
     indexed.
   - There are 3 canonical-id rows, one per group public message.
   - The database is `schema_version` 4, journal mode WAL, auto_vacuum
     INCREMENTAL, UTF-8, 172 032 bytes.
   - Ids: agent `778f61d1…f3558`, public group `40ce9dbb…34d9fa8`, secure group
     `992056be…10c8ef2` (full values in `rows.json`).
   - No group can be fork-quarantined through the REST API, so the tests pin
     the public group themselves.
6. **Excluded.** The rest of the data dir: keys, `api-token`,
   `instance.lock`, `named_groups.json` and so on.

## The scripted downgrade proof

`downgrade_proof.py` runs the older-binary half of the Validation row.
Every daemon runs under the sandbox above, with a scratch HOME. The script
uses the same config for every daemon: `dm_recording = "ephemeral"`, a
1-byte Replaceable class budget, a 31-byte `fixture.chat` topic budget and
an ephemeral `fixture.quiet` topic rule. It does not run in CI, because it
needs both binaries and macOS `sandbox-exec`.

The steps:

- **S1, upgrade (this version's `x0xd`).** It serves all 15 released rows
  and `GET /history/policy`. `POST /history/retain` deletes the two oldest
  chat rows and both cards, then reports `complete`. A self-DM and an
  ephemeral-topic message are not stored. 11 rows remain.
- **S2, downgrade (the released v0.46.6 `x0xd`, same data dir and
  config).**
  - It warns that the three ADR 0116 keys are ignored.
  - It serves the 11 rows, and full-text search works.
  - It has neither `/history/policy` nor `/history/retain`.
  - It records the DM and the ephemeral-topic message.
  - It does not apply the topic budget. 15 rows.
- **S3, upgrade again (this version's `x0xd`).** It serves all 15 rows. The
  trim enforces the topic budget again (1 chat row, 27 bytes), and the rows
  v0.46.6 recorded stay.
- **S4, newer schema.** Each binary gets a schema-5 copy and refuses it at
  start (exit 1). This version leaves the file byte-identical. The released
  v0.46.6 changes two header bytes (offsets 27 and 95), the bug fixed in
  this slice.
- After S1, S2 and S3, `verify_history_db_from_env` checks the file:
  schema 4, the v0.46.6 schema objects, FTS integrity-check, and canonical
  consistency.

```
python3 tests/fixtures/v0466_history_db/downgrade_proof.py \
  --new-x0xd target/debug/x0xd \
  --old-x0xd <scratch>/bin/x0x-macos-arm64/x0xd \
  --sandbox .planning/team-2026-10-05/loopback-only.sb \
  --fixture tests/fixtures/v0466_history_db/history.db --work <scratch>/proof \
  --verify "env HOME=<scratch>/home sandbox-exec -f <loopback-only.sb> \
    cargo nextest run --archive-file <lib archive> --workspace-remap . \
    --run-ignored only -E 'test(verify_history_db_from_env)' --no-capture"
```

## File hashes (sha256)

```
9fe7de6ea55496273df545cc1ea282107fa36a06ba701aaf6ce97dc744179baf  ./history.db
66bcab9c912e6520b4b188acc45e864a104a6d8b673dcbddb31759f9468c6ab8  ./rows.json
b01ec0681496149120bb84ec408267bb2f8eff14cfcf671ac49a3e2e5ce2e684  ./make_fixture.py
e0cb3c8d334d5dd6f582f7d31e8712f6ba0315524d11b2066731477d732c5c5d  ./downgrade_proof.py
```

`v0466_fixture_matches_its_provenance` checks `history.db` against this hash.
Regenerating the fixture produces new random keys, ids and timestamps; if
you regenerate it, update this file and the test's `FIXTURE_SHA256`.
