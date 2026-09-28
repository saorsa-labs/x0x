# Persisted-format compatibility: v0.45.0 → v0.46

Status: 2026-09-28. Fixes the v0.46 release blocker "v0.46 cannot load any
KV store snapshot written by v0.45.0" and audits every other on-disk format
changed since the `v0.45.0` tag.

## Why bincode files break

bincode 1.x (the encoding x0x uses for most binary state files) is positional
and not self-describing. A decoder reads fields in declaration order with no
tags or lengths around the struct. Two consequences:

1. `#[serde(default)]` does nothing for a field missing from an old file.
   bincode returns an end-of-file **error**, not "field absent".
2. A field added to a struct that is *followed by more data* in the same
   stream (a later field of an enclosing struct, or the next element of a
   `Vec`) reads the following bytes as its own value. The struct's
   `de_tolerant` fallback (`src/kv/store.rs`) can swallow that field's error,
   but the bytes it consumed are gone, so the next field reads from the wrong
   offset.

Adding a field is only safe when it is at the true end of the whole encoded
stream and is decoded tolerantly. Anything else needs a version marker and a
decoder for the old layout. JSON files are self-describing: new fields with
`#[serde(default)]` (or `Option`) load old files, and unknown fields are
ignored unless the struct has `deny_unknown_fields`.

## The KV snapshot blocker (fixed)

**File:** `<data_dir>/kv-stores/<store-id-hex>.bin`, one per persistent KV
store (personal, directory/self-keyed and group stores).

**v0.45.0 layout (v1):** `X0XKVS1\0 || bincode(store: KvStore) || u64
seq_counter`. `KvStore` has not changed shape from v0.38.0 to v0.45.0.

**What broke:** `KvStore.last_history_endorser` (commits 97813fa, 8bd7c64)
was appended to `KvStore` after v0.45.0. In a v1 file it sits between the
store and `seq_counter`, so it consumed the first bytes of `seq_counter` and
every v0.45.0 snapshot failed with `UnexpectedEof`. Each store was skipped at
startup and opening it through the API failed with "refusing to start with
amnesia".

**Fix (`src/kv/sync.rs`, `src/kv/store.rs`):**

- **Reading v1.** `X0XKVS1` bodies are decoded through
  `KvStoreV1SnapshotShape`, a frozen copy of the v0.45.0 `KvStore` serde shape
  (same field order, same serde attributes), then converted with
  `KvStore::from_v1_snapshot_shape`. Fields added since v0.45.0 take their
  defaults (`last_history_endorser = None`). The body must be consumed
  exactly (trailing bytes are rejected). If the v0.45.0 shape does not fit,
  the decoder tries one fallback, again consuming exactly: the v1 magic in
  front of the *current* `KvStore` shape. Only unreleased v0.46 candidate
  builds wrote that layout. At most one of the two layouts can consume a
  given body exactly, so the choice is unambiguous.
- **Writing v2.** New snapshots are `X0XKVS2\0 || bincode(SnapshotBodyV2 {
  seq_counter: u64, store: KvStore })`. The counter comes first, so the store
  runs to the true end of the stream, which is the only place `KvStore`'s
  trailing `de_tolerant` fields can default. The v2 body must also be
  consumed exactly.
- **Unknown magic** still fails closed ("refusing to start with amnesia").
- **When files change:** a v1 file is rewritten as v2 on the first persist
  after the upgrade. That is any local write or merged remote update to that
  store. Stores that are never touched stay v1.

**Tests (`src/kv/sync.rs`):**

- `v045_snapshot_fixture_loads` loads `tests/fixtures/kv_snapshot_v0_45_0.bin`,
  which v0.45.0's own `encode_snapshot` generated (see "Fixture provenance"
  below). It checks the entries, the tombstone, the rename, the
  Allowlisted policy and writer, the ownership conflict, the checkpoint and
  its high-water mark, and the exact sequence counter (13, with `version` 8).
  It fails with `UnexpectedEof` on the unfixed candidate and passes with the
  fix.
- `v045_snapshot_resaves_as_v2_and_round_trips` checks that loading v1 and
  saving again produces v2, and that v2 re-encoding is a fixed point.
- `v2_snapshot_round_trips_new_fields` round-trips `last_history_endorser`
  and the counter, and rejects trailing bytes.
- `prerelease_v1_current_shape_snapshot_still_loads` covers the candidate
  layout fallback.
- `snapshot_roundtrip_missing_and_corrupt` (extended)
  fails closed on garbage v1 and v2 bodies and on an unknown future magic.

### Downgrade: v0.46 → v0.45.0

Checked against v0.45.0's source and by running v0.45.0's `load_snapshot` on
a v2 file:

- v0.45.0 `kv::sync::load_snapshot` (`src/kv/sync.rs:1717`) strips only
  `X0XKVS1\0`. A v2 file returns
  `Err(Io("unrecognized kv snapshot format (missing v1 magic) — corrupt or foreign file; refusing to start with amnesia"))`.
- Every v0.45.0 caller fails closed on that error and returns before any
  sync or persist context exists. The callers are `create_kv_store_inner`,
  `join_kv_store_inner`, `join_self_keyed_kv_store_persistent` and
  `load_group_kv_store` (`src/lib.rs:16107/16421/16466/16566`). Their errors
  are "kv snapshot for topic … is unreadable (…); refusing to start with
  amnesia — repair or remove the snapshot file explicitly" and "group kv
  snapshot is unreadable (…)".
- At startup, `crdt_subscriptions::rehydrate_one` logs a WARN ("failed to
  rehydrate kv store after restart") or, for group stores, "encrypted store
  binding refused at restore". It returns `Skipped`, and the manifest entry
  is **kept**, so a later restart retries.
- v0.45.0 never deletes or rewrites files under `kv-stores/`. Its only
  snapshot writer is `persist_snapshot`, which needs a live sync created from
  a successful load. Its only `remove_file` in `kv/` removes its own temp
  file. The throwaway probe confirmed the v2 file is byte-identical after
  v0.45.0 tried to load it.

**Release-note statement:** *"KV store snapshots are now written in a new
format (v2). If you downgrade from 0.46 to 0.45, every KV store that 0.46
has written to is unavailable on 0.45. 0.45 logs 'unrecognized kv snapshot
format … refusing to start with amnesia' and skips the store. The snapshot
file is left untouched, and upgrading to 0.46 again restores the store with
all its data. Stores 0.46 never wrote to stay readable by 0.45."*

### Fixture provenance

`tests/fixtures/kv_snapshot_v0_45_0.bin` (1296 bytes, sha256
`508f2b60f86fdfba7adee601bd26137261af8d7cb00ca5948b5ae30e6563b903`) was
generated as follows:

1. `git worktree add --detach <scratch> v0.45.0`.
2. Add this throwaway function (never committed) to `src/kv/sync.rs` in that
   tree. It calls v0.45.0's private `encode_snapshot`:

```rust
pub fn fixture_v045_snapshot_bytes() -> Result<Vec<u8>> {
    let owner = AgentId([1; 32]);
    let writer = AgentId([2; 32]);
    let impostor = AgentId([9; 32]);
    let peer = PeerId::new([4; 32]);
    let id = KvStoreId::for_topic_owner("fixture-topic-v045", &owner);
    let mut store = KvStore::new(id, "fixture-v045".to_string(), owner, AccessPolicy::Signed)?;
    store.learn_ownership(owner, AccessPolicy::Allowlisted, 3, &owner)?;
    store.allow_writer(writer, &owner)?;
    store.put("alpha".into(), b"one".to_vec(), "text/plain".into(), peer)?;
    store.put("beta".into(), b"two".to_vec(), "application/octet-stream".into(), peer)?;
    store.put("gamma".into(), b"doomed".to_vec(), "text/plain".into(), peer)?;
    store.remove("gamma")?;
    store.update_name("fixture-v045-renamed".into(), peer);
    let _ = store.learn_ownership(impostor, AccessPolicy::Signed, 99, &impostor);
    store.latest_checkpoint = Some(crate::kv::store::OwnerCheckpoint {
        topic: "fixture-topic-v045".into(), store_id: id,
        owner_pubkey: vec![0xAB; 16], policy: AccessPolicy::Allowlisted,
        policy_version: 3, checkpoint_seq: 7, content_root: [0xCD; 32],
        timestamp: 1_790_000_000_000, signature: vec![0xEF; 8],
    });
    store.highest_checkpoint_seq = 7;
    for _ in 0..10 { let _ = store.next_seq(); }
    encode_snapshot(&store)
}
```

3. Write the bytes to a file from an example (`examples/kvsnap_fixture.rs`),
   reload them with v0.45.0's `load_snapshot`, and check the result. The
   reload gave: name `fixture-v045-renamed`, Allowlisted, `policy_version` 4,
   keys `[alpha, beta]`, ownership `Conflict`, `version` 8, next seq 14.
4. The same example put the body behind `X0XKVS2\0` and loaded it with
   v0.45.0. That produced the downgrade error above and left the file
   unchanged.

HashMap iteration order makes the bytes differ between runs. Regenerating
gives a different but equivalent file.

## Audit: every persisted format changed since v0.45.0

Method: every `Serialize`/`Deserialize` type in both trees (~500) was
extracted and diffed with comments stripped, along with every type that
contains a changed type. The load/encode functions of every persisted file
were diffed. sqlite schema/migrations and the saorsa-gossip
(0.5.81→0.5.86) and ant-quic (0.27.52→0.27.53) sources were diffed too.
These files are byte-identical between v0.45.0 and HEAD: `storage.rs`,
`key_move.rs`, `contacts.rs`, `profile.rs`, `crdt/{persistence,task_list,task_item,task,checkbox,encrypted}.rs`,
`mls/{group,treekem,welcome}.rs`, `groups/kem_envelope.rs`,
`groups/directory.rs`, `identity.rs`, `server/rider_auth.rs`,
`server/routes/files.rs`, `upgrade/mod.rs`.

**Nested `KvStore` types.** The v1 decoder reuses the current nested
types. `KvEntry`, `KvStoreId`, `OwnerCheckpoint`, `AnchorChannel` and
`AgentId` are identical to v0.45.0. saorsa-gossip `OrSet`/`LwwRegister` are
identical from 0.5.81 to 0.5.86 (only methods and a type were added).
`AccessPolicy` only gained variants at the end: v0.45.0 indices 0–4
(`Signed, Allowlisted, Encrypted, AppendOnly, SelfKeyed`) are unchanged, and
HEAD adds `GroupSigned` (5) and `TreeKemEncrypted` (6).

| Persisted item | Path | Encoding / versioning | Changed since v0.45.0? | v0.45.0 files load on v0.46? | Notes / risk |
|---|---|---|---|---|---|
| **KV store snapshot** | `kv-stores/<id>.bin` (also read by the legacy Wiki/Web import, `stores.rs` via `load_snapshot_bytes`) | `X0XKVS1` + bincode `{store, seq_counter}`; now `X0XKVS2` + `{seq_counter, store}` | `KvStore.last_history_endorser` added **mid-stream** (before `seq_counter`) | **BROKEN → FIXED in this PR** | Downgrade: fails closed without destroying data (see above) |
| Task-list snapshot | `task-lists/<id>.bin` | `X0XTLS1`/`X0XTLS2` + bincode | No (`crdt/persistence.rs`, `TaskList`, `TaskItem` identical) | SAFE | Latent: `TaskList` sits mid-stream, so any future field needs a v3 magic |
| Machine/agent/user keys, imported keys | `~/.x0x/*.key` | bincode / `X0K2` | No (`storage.rs` identical) | SAFE | |
| Agent certificate | `agent.cert` | bincode | No | SAFE | |
| Revocations v1 / v2 | `revocations.bin` (`X0XR`), `revocations-v2.bin` (`X0R2`) | magic + bincode `Vec<PersistedRevocation>` | `RevokedSubject::ShareGrant` **appended** (index 3) | SAFE | HEAD filters ShareGrant out of the v1/v2 writers, so downgrade is safe too. Latent: element sits mid-`Vec` |
| Revocations v3 | `revocations-v3.bin` (`X0R3`) | magic + bincode | New in 0.46 | n/a | |
| Key-move state | `moves.bin`, `move-bundles.bin`, `placement-blobs.bin` | magic + bincode | No (`key_move.rs` identical) | SAFE | Latent: mid-stream records |
| Agent KEM key | `agent_kem.key` | bincode | No | SAFE | |
| Announce-blob cache | `announce-blob-cache.bin` | bincode `Vec<CachedBlob>` | No | SAFE | A load failure is non-fatal |
| Share grants | `share-grants.bin` (`X0SG`) | magic + bincode | New in 0.46 | n/a | Latent: no body version; future `ShareGrant` fields need a new magic |
| Share-grant outbox | `share-grant-outbox.bin` (`X0GO`) | magic + bincode | New in 0.46 | n/a | Same latent hazard |
| TreeKEM state | `treekem/<gid>.snap`, `.journal`, `.hsjournal`; `member-key-packages.json` | postcard (positional); JSON | No (types and codec functions identical) | SAFE | |
| MLS groups | `mls_groups.bin` | n/a | Never written in either version | n/a | |
| History | `history.db` | sqlite, `SCHEMA_VERSION = 4` in both | Only a connection-local TEMP table | SAFE | |
| Contacts | `contacts.json` | JSON | No | SAFE | |
| Profiles | `owner.json`, `profile.json`, `owner-cert-journal.jsonl` | JSON | No | SAFE | |
| Owner sync | `sync/records.json`, `sync/devices.json` | JSON | No | SAFE | |
| Named groups | `named_groups.json`, `home-suite-groups.json` | JSON | Nested `InviteLineage.anchored_gap_refusal: Option<_>` with `serde(default)` | SAFE | |
| Causal approval queue | `causal_approval_queue.json` | JSON | `NamedGroupMetadataEvent` + 4 fields, all `serde(default)` | SAFE | |
| Predecessor relay outbox | `predecessor_relay_outbox.json` | JSON | No | SAFE | |
| Public-group bootstrap outbox | `public_group_bootstrap_outbox.json` | JSON `{version: 1}` | Struct unchanged; loader now refuses `fork_quarantine` | SAFE | v0.45.0 already stripped `fork_quarantine` when writing these |
| Requester-offer outbox | `requester_offer_outbox.json` | JSON | New in 0.46 | n/a | |
| CRDT / directory subscriptions | `crdt-subscriptions.json`, `directory-subscriptions.json` | JSON | No | SAFE | |
| Rider tokens, home marker | `rider-tokens.json`, `home.json` | JSON | No | SAFE | |
| API token/port, instance lock | `api.token`, `api.port`, `instance.lock` | text | No (lock code moved to `file_lock.rs`) | SAFE | |
| Upgrade handoff | `upgrade-handoff.json` | JSON | + `systemd_verified: Option<_>` `serde(default)` | SAFE | v0.45.0 ignores the unknown field |
| Daemon config | x0xd `config.toml` | TOML | `GossipConfig` + 2 fields with defaults | SAFE | |
| Exec ACL | `exec-acl.toml` | TOML, `deny_unknown_fields` | Entries gain optional `principal`; ids become optional | SAFE (forward) | **Downgrade:** a file that uses `principal` is rejected by v0.45.0 |
| Connect ACL | connect-acl TOML | TOML, `deny_unknown_fields` | Same as exec ACL | SAFE (forward) | **Downgrade:** same as exec ACL |
| ACL overlays | `acl/…` | JSON, `OVERLAY_VERSION = 1` | New in 0.46 | n/a | |
| Legacy import intents / journal | `kv-stores/legacy-page-import-intents-v1/*` | JSON, version 1 | New in 0.46 | n/a | |
| Bootstrap cache | `peers/bootstrap_cache.json` | ant-quic owned | No cache changes in 0.27.53 | SAFE | |
| Transfers | `transfers/` | raw spool | No | SAFE | |
| Exec audit log | configured | JSONL | Trivial | SAFE | |

No filesystem persistence at all: `forward.rs`, `dm_inbox.rs`, `dm.rs`,
`server/delegations.rs`, `trust.rs`, `calls.rs`, `owner_trust.rs`.

**Result:** the KV snapshot is the only persisted format whose v0.45.0
files fail to load on v0.46, and this PR fixes it. The other downgrade
risks are the v2 KV snapshot (fails closed, no data loss) and ACL TOML that
uses the new `principal` key. The latent positional hazards above are not
broken today. Any new field on `TaskList`/`TaskItem`,
`PersistedRevocation`, key-move records, `ShareGrant` or
`PendingGrantDelivery` must come with a new file magic and a frozen decoder
for the old layout, following the KV snapshot pattern here.
