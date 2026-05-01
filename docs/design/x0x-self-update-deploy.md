# Self-update-driven deploys (Phase C extension)

**Status:** design — not implemented
**Filed:** 2026-05-01
**Owner:** TBD (deferred from Phase C of the dogfood-test refactor)
**Related:** [TEST_SUITE_GUIDE.md §7b](../../TEST_SUITE_GUIDE.md), `docs/design/p2p-timeout-elimination.md`, `src/upgrade/`

## Problem

Today, `tests/e2e_deploy.sh` distributes a new `x0xd` binary by SSHing
to each VPS and running `cat | systemctl restart`. With the Phase-A
mesh harness verified by `--mesh-verify`, post-deploy checks are
already SSH-free — but the **binary push itself** still costs 2–4 SSH
calls per node (one connection check, one upload, one restart). On
six nodes that's 12–18 SSH operations per release; on a 12-node fleet
it's 24–36.

The daemon already ships the cryptographic machinery to make those
SSH ops unnecessary:

- `src/upgrade/manifest.rs` defines `ReleaseManifest` (signed JSON,
  ML-DSA-65)
- `src/upgrade/signature.rs` signs/verifies manifests
- `src/upgrade/monitor.rs` listens on the `x0x/releases` gossip topic
  and downloads the announced archive
- `src/upgrade/apply.rs` does the atomic binary replacement with
  rollback
- `src/upgrade/rollout.rs` provides a deterministic per-machine
  staggered delay

This is exactly what we need for "deploy via gossip", with one missing
piece: the **release-signing key is GitHub-only**. A test or operator
deploying a custom build cannot publish a manifest the fleet will
accept.

## Proposal

Three small additions, all daemon-side and additive:

### 1. Test-mode signing key (`x0xd --test-trust-key <path>`)

When set, the daemon accepts release manifests signed by **either** the
embedded production release key **or** the test public key loaded from
the file. The flag is parsed once at startup and the key is held in
the same `Arc<TrustedReleaseKeys>` structure already in `signature.rs`.

Restrictions:

- Off by default. Production fleets never carry a test key.
- Audit-logged at WARN level on every manifest application:
  ```
  [release-trust] applied test-keyed manifest sig=<hex> from=<peer_id>
  ```
- Documented as "for CI/test fleets only" in `docs/exec.md`-style
  operator notes.

### 2. `x0x upgrade publish` CLI verb (~80 lines)

A new subcommand that:

1. Reads a local archive (`.tar.gz` of the binary + sha256).
2. Builds a `ReleaseManifest` for the supplied platform target.
3. Signs the manifest with a key file path (test key by default;
   production builds reject the verb if `cfg!(release_signing_key)` is
   present, refusing to risk re-signing the canonical manifest).
4. Publishes both the manifest and the signed envelope on the
   existing `x0x/releases` gossip topic.

Wire format unchanged — daemons already know how to consume manifests
on that topic; they just need to trust the test signature too.

### 3. `tests/e2e_deploy_mesh.sh` (harness)

```bash
# Cold-start: SSH-once to a single seed VPS, scp the binary + ed25519
# trust key (one connection per fleet) so seeds carry the test key on
# every restart. After the very first cold start, all subsequent
# deploys ride x0x:

bash tests/e2e_seed_keys.sh           # one-time setup, 1 SSH/node
cargo zigbuild --release --target x86_64-unknown-linux-gnu

# Deploy via gossip:
target/release/x0x upgrade publish \
    --archive target/x86_64-unknown-linux-gnu/release/x0xd.tar.gz \
    --signing-key tests/.test-release-key \
    --target x86_64-unknown-linux-gnu \
    --version 0.19.18

# That single command:
#   • signs the manifest with the test key
#   • publishes on x0x/releases
#   • each fleet node verifies via the trusted test key,
#     applies via upgrade::apply, restarts itself

# Verify the new build via the mesh harness:
python3 tests/e2e_vps_mesh.py --anchor nyc
python3 tests/e2e_vps_groups.py --anchor nyc
```

After the one-time seed of trust keys, **every subsequent deploy is
zero SSH** and naturally acquires symmetric gossip propagation,
quality-scored bootstrap-cache enrichment, and per-machine rollout
staggering — properties the SSH-driven path doesn't have.

## Acceptance criteria

1. `x0xd --test-trust-key /path/to/test.pub` accepts manifests signed
   by either key; without the flag, the daemon refuses test-signed
   manifests.
2. `x0x upgrade publish` end-to-end on a 3-daemon local mesh: deployed
   binary swap on all three within 30 s, no SSH involved.
3. Audit-log entry for every test-keyed manifest application.
4. Existing GitHub-release-driven path (production key, daemon polls
   GitHub) is unaffected.
5. `tests/e2e_deploy_mesh.sh` deploys to all 6 VPS via gossip after a
   one-time seed, and `tests/e2e_vps_mesh.py --anchor nyc` reports a
   clean matrix on the new build.

## Why this isn't being implemented now

This work overlaps materially with the Tier-1 exec feature being
shipped by another team (`docs/design/x0x-exec.md`): both add a flag
on `x0xd`, a new CLI verb, and a small chunk of daemon-side validation
logic. Landing it concurrently risks merge churn in `src/dm.rs`,
`src/cli/mod.rs`, `src/api/mod.rs`, and `docs/design/api-manifest.json`
— the same files exec is touching.

Schedule for after exec PR 4 lands.

## Out-of-scope reminders

- No changes to the production release-signing process. CI continues
  to mint and embed the production key as today.
- No "any signature accepted" mode. Even in test-mode, every manifest
  must be ML-DSA-65 signed by a key the daemon was explicitly told to
  trust.
- No remote arbitrary code execution. The fetch URL is constrained to
  HTTPS and the SHA-256 of the archive must match the manifest claim.
