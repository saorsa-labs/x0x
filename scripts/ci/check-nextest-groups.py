#!/usr/bin/env python3
"""Check that every nextest test group has one `threads-required` value.

nextest before 0.9.151 schedules with `future_queue_grouped` from
future-queue 0.4.0. A test
queued behind a full group is retried only when a test of the same group
finishes, and it starts only if the global limit has room for its own
weight then. When a group mixes weights, a heavier head can stay queued
after a lighter test of its group frees too little room, and the run ends
with tests "not run" and no failure. One weight per group rules that out.
future-queue 0.4.1 (nextest-rs/future-queue#603, first used by
cargo-nextest 0.9.151) fixes the scheduler; the check stays as a guard for
any nextest version.

nextest resolves `test-group` and `threads-required` field by field: each
comes from the first matching override that sets it. An override that sets
only one of them can therefore pair a group with another override's
weight (a weight-only override that matches a grouped test, or a
group-only override ahead of a weighted one). The check does not evaluate
filters, so it requires:
- every override sets both `test-group` and `threads-required`, or
  neither;
- each test group has one `threads-required` value across every profile
  (custom profiles also apply the default profile's overrides).
"""
import sys
import tomllib
from pathlib import Path

CONFIG = Path(__file__).resolve().parents[2] / '.config' / 'nextest.toml'


def check(config):
    errors = []
    weights = {}
    for name, profile in config.get('profile', {}).items():
        for index, override in enumerate(profile.get('overrides', [])):
            group = override.get('test-group')
            weight = override.get('threads-required')
            where = f'profile {name!r} override {index} ({override.get("filter", "?")!r})'
            if (group is None) != (weight is None):
                errors.append(
                    f'{where} sets only one of test-group and threads-required; '
                    'set both or neither'
                )
            if group is not None and weight is not None:
                weights.setdefault(group, set()).add(weight)
    for group, values in sorted(weights.items()):
        if len(values) > 1:
            errors.append(
                f'test group {group!r} mixes threads-required '
                f'{sorted(values, key=str)}; use one value for the whole group'
            )
    return errors


def main():
    with CONFIG.open('rb') as handle:
        config = tomllib.load(handle)
    errors = check(config)
    for error in errors:
        print(f'error: {error}', file=sys.stderr)
    if errors:
        return 1
    print('nextest test groups: paired overrides, one threads-required value per group')
    return 0


if __name__ == '__main__':
    sys.exit(main())
