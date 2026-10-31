# H-S3-home fixture: provenance

Candidate data directories that hold the ADR 0109 §4 S3 Home placeholder.
The H-S3-home gate (#1571) starts the released binaries on copies of them.
`h_s3_home_fixture_loads` loads them on every test run (ADR 0085 rule 6).

## How it was made (2026-10-31)

- Generator: `src/server/routes/named_groups/group_recovery/h_s3_home_fixture.rs`,
  test `generate_h_s3_home_fixture` (ignored). Command:
  `cargo nextest run --all-features --lib --run-ignored only -E 'test(generate_h_s3_home_fixture)'`.
- Encoder: the candidate's own code, on branch `claude/issue-1571`, based on
  #1626 (`18b0d73d`). Keys, the agent certificates and the user key use the
  `x0x::storage` encoders. The creator O provisions its Home through
  `provision_home`, which also writes `home.json`.
- O seats a promoted admin A2 and the two J devices. Each seat has an
  owner-issued agent certificate. O seals the roster through
  `seal_commit_owner_certified`.
- Home activation is on by test configuration (`activate_home`). A2 signs
  an ATA for each subject, and the real arming path (`arm_in_place`)
  writes the sidecar and the legacy placeholders.
- Variants:
  - `creator`: O. Owner install with `identity/user.key` and `home.json`.
  - `owner_device`: J with the owner's user key and its own agent certificate.
  - `device`: J with an agent certificate and no user key.
- Kept files: `identity/{machine,agent,user}.key`, `identity/agent.cert`,
  `named_groups.json`, `home-suite-groups.json`, `home.json` (creator only)
  and `group-recovery/<stable_group_id>.grecov`. The owner-sync store
  (`sync/`) is not kept, so no canonical Home pointer is stored.
- The owner user key comes from the fixed seed `0x16` × 32. The agent and
  machine keys are random. **All keys are test-only.** They never touched
  a network.
- `manifest.json` lists, for each variant: the agent ID, the group key, the
  expected group-ID set, the `home.json` sha256 (or null), the sidecar path
  and sha256, whether the variant is an owner install, and whether it is
  an expected failure. ADR 0109 §4 "Risk" predicted that owner installs
  fail. The first measured run (31 Oct 2026, released macOS arm64
  binaries, loopback-only sandbox, 2 × 150 s) showed every variant pass on
  v0.45.0 and v0.46.1, so no variant is an expected failure.

## Not deterministic

ML-DSA signatures, the random agent and machine keys, and timestamps change
on each run. The layout and the placeholder form do not change. If you
generate the fixture again, update the hashes below.

## ADR 0085 rule 6 status

This is the candidate encoder's fixture. No release writes `X0GRCV1` yet.
Under the Engineer's 29 Oct 2026 ruling on #1571, the release-artifact
provenance step waits for the first release that writes it. That step
stays open on #1571.

## File hashes (sha256)

```
3a593d6ec6d4cd0598ed2fa712cb302a4052acdd9d0831a4f1430f4e7cbaedaa  ./creator/group-recovery/4bb0c6e2233f0a137e563ae0bf81c632e404b571588732e3c04da79a6cca1cbe.grecov
d1ebf157fea6ed3716964031043f2c9a4ce8adb3e955f4a1fc3f96aaae97f7c6  ./creator/home-suite-groups.json
7ae8cbd7b35fbf76b9cb4f382de471c01803bcb03236672ac313a27eba1b3e5f  ./creator/home.json
cf41ea470162ca21daeb9ba08b53f4bffd568776e4911cd3cdbb8f0f898df007  ./creator/identity/agent.cert
85747849331c13706684878454ec7d2d347649be27c9054b8ce56fa32c273975  ./creator/identity/agent.key
e121dfd979c10ad6a1b370e96b4c08807a7572b19a71eaa972fe90155b2e6dc3  ./creator/identity/machine.key
f5777cb44ddce9f537459efbb67a8f14f3227a281cc7f15f16eee38b3dbbc0d6  ./creator/identity/user.key
521d62ac8746ce012e64f048e064c56eaf1e09dde300b236e97dd1b91067757a  ./creator/named_groups.json
79f0c85ef91f1158f2360595bb3e192d5cc8cbf37fcbbd3a20a28d2fb9b33463  ./device/group-recovery/4bb0c6e2233f0a137e563ae0bf81c632e404b571588732e3c04da79a6cca1cbe.grecov
d1ebf157fea6ed3716964031043f2c9a4ce8adb3e955f4a1fc3f96aaae97f7c6  ./device/home-suite-groups.json
c5eca4c41d4cb81510438b6a5cf65bd459dd6ca817e63cf41cbe6e98d7dd694d  ./device/identity/agent.cert
734149047eef2182bcb5c710c0727b59c3789427536b446462374f62c311c80c  ./device/identity/agent.key
b73fce8571985ee035b8390cd5a54a5df86c024c6929ddf8d3eebcf0f034ae6c  ./device/identity/machine.key
521d62ac8746ce012e64f048e064c56eaf1e09dde300b236e97dd1b91067757a  ./device/named_groups.json
80450754b184e27675995e443f9703e7074042b80c99aec4468272c19cf48a4a  ./manifest.json
babf732e45c2b2a63edc8a5571f95efbe2f1125c5b7482b14c9c1bcc0f0487c3  ./owner_device/group-recovery/4bb0c6e2233f0a137e563ae0bf81c632e404b571588732e3c04da79a6cca1cbe.grecov
d1ebf157fea6ed3716964031043f2c9a4ce8adb3e955f4a1fc3f96aaae97f7c6  ./owner_device/home-suite-groups.json
d5f66bab0187b1d41b967c46e44c24165a70745e630e8a009930fdc0ff4df10f  ./owner_device/identity/agent.cert
bd6b3a60e9ffa4cf4d619a72dd49f75f85cf37fda9d52da25071e06f95ef9a56  ./owner_device/identity/agent.key
b8d28746703d8867c70c27fb63e00f923de2f87097a21e440abab8ba7b6eefd3  ./owner_device/identity/machine.key
f5777cb44ddce9f537459efbb67a8f14f3227a281cc7f15f16eee38b3dbbc0d6  ./owner_device/identity/user.key
521d62ac8746ce012e64f048e064c56eaf1e09dde300b236e97dd1b91067757a  ./owner_device/named_groups.json
```
