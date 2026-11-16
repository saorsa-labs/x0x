#!/usr/bin/env python3
"""Check that every nextest test group has one `threads-required` value.

nextest schedules with `future_queue_grouped` (future-queue 0.4.0). A test
queued behind a full group is retried only when a test of the same group
finishes, and it starts only if the global limit has room for its own
weight then. When a group mixes weights, a heavier head can stay queued
after a lighter test of its group frees too little room, and the run ends
with tests "not run" and no failure. One weight per group rules that out.
future-queue 0.4.1 (nextest-rs/future-queue#603, cargo-nextest 0.9.151)
fixes the scheduler; CI pins cargo-nextest 0.9.144.

Each override counts with its own value (1 when it sets none). The check
does not evaluate filters, so a group override always states its value.
"""
import sys
import tomllib
from pathlib import Path

CONFIG = Path(__file__).resolve().parents[2] / '.config' / 'nextest.toml'


def check(config):
    errors = []
    for name, profile in config.get('profile', {}).items():
        weights = {}
        for override in profile.get('overrides', []):
            group = override.get('test-group')
            if group is None:
                continue
            weights.setdefault(group, set()).add(override.get('threads-required', 1))
        for group, values in sorted(weights.items()):
            if len(values) > 1:
                errors.append(
                    f'profile {name!r}: test group {group!r} mixes threads-required '
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
    print('nextest test groups: one threads-required value per group')
    return 0


if __name__ == '__main__':
    sys.exit(main())
