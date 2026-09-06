# One-run #531 Linux diagnostic

This branch's `build.yml` is a **manual-only diagnostic variant, not for merge**.
Root review, exact-tree gates, push approval and a separate dispatch decision are
required before any GitHub execution. No release, signing, PR or public workflow
change is implied by local preparation.

The workflow pins Rust1.98.1 and nextest0.9.143 on a disposable Ubuntu24.04 VM,
uses the retained local proof lock, and checks production-source equivalence with
baselinee16ba97 and the historic CI tree. It builds debug/all-features with CI's
flags, retains Cargo JSON and a nextest archive, then admits exactly one ignored
ban-redelivery test only after synthetic fence controls. The test's30s deadline,
resend offsets and setup/snapshot assertions remain unchanged.

`namespace.sh` enters a new network/PID/mount namespace: only loopback, no external
route, a private/tmp for the unchanged nextest home wrapper, and namespace-local
nftables. `fence.nft` allows only the two fixture APIs, established TCP replies,
and both ends of the two QUIC port tuples. Product children have zero capability
sets and no-new-privileges. The PID1 coordinator owns teardown and checks sockets;
namespace destruction also removes any remaining descendants. It never changes
host firewall rules or kills processes by port. Actual ant-quic wildcard UDP binds
are contained in the loopback-only namespace. mDNS stays internally enabled in
exact source but is loopback-suppressed and independently fenced; UPnP is off.

Synthetic controls use real request/reply and outside-the-client receive counters
for both address families, plus firewall drop counters. Linux DROP need not return
EPERM. Failure stops admission; no rule widening or retry exists. These Linux
controls have **not been run on this Mac**. The offline Python tests exercise the
actual selection/socket/collector helpers, not kernel isolation.

The collector uploads only explicitly named evidence and daemon log files; raw
data, identity directories and API-token files are excluded. Collection still runs
after a failed fixture, but upload requires the collector step to succeed; a
rejected pre-existing upload directory is never published. A cancellation can
prevent upload; missing receipts mean incomplete evidence, never a pass. The job
keeps the original20-minute limit; nextest retries are0. A single passing Linux run
would not explain the historic failure or preceding-test/load interaction.

The historical CI used the same logged ant-quic0.27.48 and gossip0.5.75 versions,
but retained no full lock artifact. The pinned lock here is not claimed to recreate
all historic560-package resolutions. Image revision and kernel may differ and are
recorded. The original local proof remains untouched in the separate Mac worktree.
