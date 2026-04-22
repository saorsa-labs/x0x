# x0x v0.18.5 machine-centric discovery proof

Date: 2026-04-22

## Change under proof

Machines are now first-class discovery targets:

- signed `x0x.machine.announce.v1` machine endpoint announcements
- discovered-machine cache keyed by `machine_id`
- agent/user identity links onto the current `machine_id`
- machine-centric REST endpoints and `Agent::connect_to_machine`

## Gates run

- `cargo fmt --all` — pass
- `cargo check --all-features` — pass
- `cargo clippy --all-features -- -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used` — pass
- `cargo test --all-features --test announcement_test --test connectivity_test --test api_coverage` — pass
  - `announcement_test`: 13 passed
  - `api_coverage`: 8 passed
  - `connectivity_test`: 22 passed

## Full-suite note

`cargo nextest run --all-features --workspace` completed the build phase but
hung in nextest test discovery/listing with many long-lived `--list --format
terse` child processes. The run was interrupted and orphaned child processes
were terminated; no test failure output was produced before the discovery hang.
