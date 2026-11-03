#!/usr/bin/env python3
"""Split W3-H cases across CI shards without dropping or shortening a case.

Each shard runs its cases with the same `--stress-count 20` gate profile.
The summary job merges the trace directories and runs `w3h-trace-check.py`.
A case name matches exactly one shard. A new `w3h_1356_` or `w3h_1357_`
case joins the S3 or S4 shard. Any other new `w3h_` case joins `rest`.
The four ADR 0109 owner-axis rows (H-S3-c, H-S3-c2, H-S3-c3, H-S3-d8)
each have their own shard: one rerun of each row is the longest S3 case,
and 20 reruns of them in one job do not fit the S3 test deadline.

The S3 shard is omitted when the tree has no `w3h_1356_` test, so `main`
does not spend a runner on an empty filter. Adding those tests makes the
shard appear on the next plan.
"""
import argparse
import json
import re
import sys
from pathlib import Path

# First match wins. `rest` is every w3h_ test that matches none of these.
# Each pattern is a regular expression on the test function name (not a
# module path), anchored at its start. A pattern that ends in `$` names one
# case. The owner-axis rows come before `s3`, so `s3` takes the other
# `w3h_1356_` cases.
GROUPS = (
    ('long-1023', 'w3h_1023_'),
    ('s4', 'w3h_1357_'),
    ('s3-c', 'w3h_1356_red_s3_c_promoted_admin_reseats_owner_axis_node$'),
    ('s3-c2', 'w3h_1356_red_s3_c2_reseat_retires_marker_and_gap$'),
    ('s3-c3', 'w3h_1356_control_s3_c3_owner_reseats_owner_axis_node$'),
    ('s3-d8', 'w3h_1356_control_s3_d8_removal_basis_reseats_owner_axis_node$'),
    ('s3', 'w3h_1356_'),
)

ROOT = Path(__file__).resolve().parents[2]


def group_of(name):
    """Return the shard id for one test function name."""
    for group, pattern in GROUPS:
        if re.match(pattern, name):
            return group
    return 'rest'


def filter_expr(group):
    """Nextest filterset for one shard.

    The `w3h-gate` profile already intersects this with
    `test(/(^|::)w3h_/)`. A group excludes the patterns of the groups
    before it, and `rest` excludes all of them, so a case cannot run twice.
    """
    names = [name for name, _pattern in GROUPS]
    if group == 'rest':
        earlier = GROUPS
    elif group in names:
        earlier = GROUPS[:names.index(group)]
    else:
        raise SystemExit(f'unknown W3-H shard {group!r}')
    clauses = [f'not test(/(^|::){pattern}/)' for _name, pattern in earlier]
    if group != 'rest':
        clauses.insert(0, f'test(/(^|::){dict(GROUPS)[group]}/)')
    return ' and '.join(clauses)


def discover(root=ROOT):
    """Return sorted `w3h_` lib-test function names under `root`/`src`.

    A `#[test]` or `#[tokio::test]` attribute applies to the next function.
    Blank lines, doc comments and other attributes (for example `#[ignore]`)
    stay inside that attribute. Only functions whose names start with `w3h_`
    are cases; the profile filter does not run any other test.
    """
    names = []
    src = Path(root) / 'src'
    for path in sorted(src.rglob('*.rs')):
        pending = False
        for line in path.read_text(encoding='utf-8').splitlines():
            if re.search(r'#\[(?:[\w:]+::)?test\b', line):
                pending = True
                continue
            if not pending:
                continue
            match = re.search(r'\bfn\s+(w3h_[A-Za-z0-9_]+)\s*\(', line)
            if match:
                names.append(match.group(1))
                pending = False
                continue
            if re.search(r'\bfn\s+[A-Za-z0-9_]+\s*\(', line):
                pending = False
    if len(names) != len(set(names)):
        dupes = sorted({name for name in names if names.count(name) > 1})
        raise SystemExit(f'duplicate w3h test names: {dupes}')
    return sorted(names)


def assign(names):
    """Map shard id -> sorted case names. Empty shards are omitted."""
    buckets = {}
    for name in names:
        buckets.setdefault(group_of(name), []).append(name)
    return {group: sorted(cases) for group, cases in buckets.items()}


def matrix(names):
    """GitHub Actions matrix. Group order follows GROUPS, then `rest`."""
    assigned = assign(names)
    order = [group for group, _pattern in GROUPS if group in assigned]
    if 'rest' in assigned:
        order.append('rest')
    return {'group': order}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix', action='store_true',
                        help='print the GitHub Actions matrix JSON')
    parser.add_argument('--filter', metavar='GROUP',
                        help='print the nextest filterset for GROUP')
    parser.add_argument('--list', metavar='GROUP',
                        help='print case names for GROUP, one per line')
    parser.add_argument('--root', type=Path, default=ROOT,
                        help='repository root (default: this repo)')
    args = parser.parse_args(argv)
    names = discover(args.root)
    if args.matrix:
        print(json.dumps(matrix(names), separators=(',', ':')))
        return 0
    if args.filter:
        # Validate the group exists in this tree when it is a named shard
        # that currently has cases, but still print a filter for an empty
        # named shard so a caller can see the expression.
        print(filter_expr(args.filter))
        return 0
    if args.list:
        cases = assign(names).get(args.list, [])
        if not cases:
            raise SystemExit(f'W3-H shard {args.list!r} has no cases')
        print('\n'.join(cases))
        return 0
    parser.error('pass --matrix, --filter GROUP, or --list GROUP')
    return 2


if __name__ == '__main__':
    sys.exit(main())
