#!/usr/bin/env python3
"""Split W3-H cases across CI shards without dropping or shortening a case.

Each shard runs its cases with the same `--stress-count 20` gate profile.
The summary job merges the trace directories and runs `w3h-trace-check.py`.
A case name matches exactly one shard. A new `w3h_1356_` or `w3h_1357_`
case joins the S3 or S4 shard. Any other new `w3h_` case joins `rest`.
The five ADR 0109 owner-axis rows (H-S3-c, H-S3-c2, H-S3-c3, H-S3-d8,
H-S3-d3) each have their own shard: one rerun of each row is the longest
S3 case, and 20 reruns of them in one job do not fit the S3 test deadline.
One rerun of H-S3-d3 takes about 16 min on a runner, so its 20 reruns
are split across parallel parts (`PARTS`): matrix entries `s3-d3.1` to
`s3-d3.4`, 5 reruns each. The #1661 welcome-lost row has its own shard
too, split as `s3-1661.1` and `s3-1661.2`, 10 reruns each. The H-S3-rm4
variants run the H-S3-c prefix and share one shard, split as `s3-rm4.1`
and `s3-rm4.2`, 10 reruns each. H-S3-rm2 runs the H-S3-d3 five-node
prefix with M1 seated, then the H-S3-c advance and re-seat; it has its
own shard, split as `s3-rm2.1` and `s3-rm2.2`, 10 reruns each. H-S3-d2
has its own shard (`s3-d2`). The summary job still counts 20 receipts.

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
    ('s3-d3', 'w3h_1356_control_s3_d3_authorisation_refusals_typed$'),
    ('s3-1661', 'w3h_1356_red_1661_welcome_lost_after_readmission_ends_typed$'),
    ('s3-rm4', 'w3h_1356_control_s3_rm4_'),
    ('s3-rm2', 'w3h_1356_control_s3_rm2_reseat_mandate_refusals_typed$'),
    ('s3-d2', 'w3h_1356_control_s3_d2_fork_exposure_contained$'),
    ('s3', 'w3h_1356_'),
    # #1623 (refs #1356): about 11 s per rerun on macOS; `rest` already
    # takes about 104 of its 120 minutes (run 41624339394), so the row
    # has its own shard.
    ('1623', 'w3h_1623_'),
)

# The gate's reruns per case (D196). A group in `PARTS` runs them as that
# many parallel matrix entries `<group>.<k>`, each with its share of RUNS.
RUNS = 20
# H-S3-d3 (#1572): one rerun is 940-1000 s on a 4-vCPU runner (job
# 125609571831), so 20 reruns (about 320 min) do not fit the 155-min S3
# test deadline or the 360-min hosted job limit. 4 parts of 5 reruns take
# about 85 min each.
# #1661 welcome-lost row: one rerun is about 230 s on a 12-CPU VM, so about
# 460 s on the runner; 20 reruns (about 153 min) leave almost no margin
# under the 155-min S3 test deadline. 2 parts of 10 reruns take about
# 80 min each.
# H-S3-rm4 (1) and (2): one rerun of both is about 220 s in the 12-CPU VM,
# so about 440 s on the runner; 20 reruns (about 147 min) leave almost no
# margin under the 155-min S3 test deadline. 2 parts of 10 reruns take
# about 75 min each.
# H-S3-rm2: one rerun took about 161 s in the 12-CPU Lima VM, so about
# 320 s on the runner (the #1780 ratio; no runner measurement yet), and
# 20 reruns about 107 min. That estimate is not a clear margin under the
# 155-min S3 test deadline, so split it, do not raise the budget (31 Oct
# ruling, #1733): 2 parts of 10 reruns take about 55 min each.
PARTS = {'s3-d3': 4, 's3-1661': 2, 's3-rm4': 2, 's3-rm2': 2}

ROOT = Path(__file__).resolve().parents[2]


def split_part(entry):
    """`(group, part, parts)` for a matrix entry: `s3-d3.2` is part 2 of
    `PARTS['s3-d3']`; a group with no parts is part 1 of 1."""
    group, dot, part = entry.partition('.')
    parts = PARTS.get(group, 1)
    if not dot:
        if parts != 1:
            raise SystemExit(f'W3-H shard {group!r} runs as parts {group}.1..{parts}')
        return group, 1, 1
    if not part.isdigit() or not 1 <= int(part) <= parts or parts == 1:
        raise SystemExit(f'unknown W3-H shard part {entry!r}')
    return group, int(part), parts


def stress_count(entry):
    """Reruns for one matrix entry. The parts of a group add up to RUNS."""
    group, part, parts = split_part(entry)
    if group != 'rest' and group not in dict(GROUPS):
        raise SystemExit(f'unknown W3-H shard {group!r}')
    return RUNS // parts + (1 if part <= RUNS % parts else 0)


def tag_traces(entry, directory):
    """Rename `<case>-<pid>.<ext>` to `<case>-p<k>_<pid>.<ext>` for part k,
    so traces of the same case from parallel parts cannot share a name
    when the summary job merges them (a runner can reuse a pid). The
    trace check reads the case as the text before the last `-`. Returns
    the number of files renamed; a group with no parts renames none.

    The pid-less dump markers `<case>.first-digest` and
    `<case>.divergent-digest` are not renamed: each part writes its own,
    and the merge keeps one of them. Only the run that writes them reads
    them (to choose which runs dump payloads), so the merged copy is not
    used."""
    _group, part, parts = split_part(entry)
    if parts == 1:
        return 0
    renamed = 0
    for path in sorted(Path(directory).iterdir()):
        stem, dot, ext = path.name.partition('.')
        case, dash, pid = stem.rpartition('-')
        if not (path.is_file() and dot and dash and case and pid.isdigit()):
            continue
        path.rename(path.with_name(f'{case}-p{part}_{pid}.{ext}'))
        renamed += 1
    return renamed


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
    if '.' in group:
        group = split_part(group)[0]
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
    """GitHub Actions matrix. Group order follows GROUPS, then `rest`; a
    group in PARTS is listed as its parts."""
    assigned = assign(names)
    order = [group for group, _pattern in GROUPS if group in assigned]
    if 'rest' in assigned:
        order.append('rest')
    entries = []
    for group in order:
        parts = PARTS.get(group, 1)
        entries += [group] if parts == 1 else [f'{group}.{k}' for k in range(1, parts + 1)]
    return {'group': entries}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix', action='store_true',
                        help='print the GitHub Actions matrix JSON')
    parser.add_argument('--filter', metavar='GROUP',
                        help='print the nextest filterset for GROUP')
    parser.add_argument('--list', metavar='GROUP',
                        help='print case names for GROUP, one per line')
    parser.add_argument('--stress', metavar='GROUP',
                        help='print the --stress-count for GROUP (a matrix entry)')
    parser.add_argument('--tag-traces', nargs=2, metavar=('GROUP', 'DIR'),
                        help='rename the trace files in DIR for part GROUP')
    parser.add_argument('--root', type=Path, default=ROOT,
                        help='repository root (default: this repo)')
    args = parser.parse_args(argv)
    names = discover(args.root)
    if args.matrix:
        print(json.dumps(matrix(names), separators=(',', ':')))
        return 0
    if args.stress:
        print(stress_count(args.stress))
        return 0
    if args.tag_traces:
        entry, directory = args.tag_traces
        print(f'W3-H shard {entry}: renamed {tag_traces(entry, directory)} trace files')
        return 0
    if args.filter:
        # Validate the group exists in this tree when it is a named shard
        # that currently has cases, but still print a filter for an empty
        # named shard so a caller can see the expression.
        print(filter_expr(args.filter))
        return 0
    if args.list:
        group = split_part(args.list)[0] if '.' in args.list else args.list
        cases = assign(names).get(group, [])
        if not cases:
            raise SystemExit(f'W3-H shard {args.list!r} has no cases')
        print('\n'.join(cases))
        return 0
    parser.error('pass --matrix, --filter, --list, --stress or --tag-traces')
    return 2


if __name__ == '__main__':
    sys.exit(main())
