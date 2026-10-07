#!/usr/bin/env python3
"""W3-H (#1164) gate: verdict-stable reruns (ruling D196).

Every W3-H case writes its canonical trace to `<case>-<pid>.trace` (see
`Sim::finish`), and the red-baseline cases also write a structured receipt
to `<case>-<pid>.receipt.json` (schema `w3h.receipt/1`). After a
`--stress-count N` run, this script requires, for every case:

- at least one trace in the directory, so a run can never pass vacuously;
- exactly N traces (`--runs N`): every rerun finished and wrote its trace;
- the trace recorded `entropy=controlled` (the preload shim was active).

`--require CASE` names cases that must be present.

`--expect CASE=VERDICT` (RED, GREEN or INFRA) checks that case's receipts:
exactly `--runs` of them, every one with that verdict (so all reruns agree),
and every one complete:

- RED: `setup_done`, at least one `evidence` stage and every one ok, an ok
  `request_delivered`, at least one `cause` stage and every one ok, and a
  failed `final`;
- GREEN: the same, except that `cause` is not required and `final` passed.

Byte-identical traces are REPORTED, not required (D196): the script prints
the number of distinct traces per case and the first divergence. With
`--strict-traces` a case with more than one distinct trace fails, for
determinism work. A trace file is the digested canonical trace (everything
up to the `teardown begins` mark), then an `APPENDIX` line and the teardown
events; only the digested part is compared. Exit 1 on any failure.
"""
import json
import argparse
import difflib
import hashlib
import sys
from collections import defaultdict
from pathlib import Path

# Must match `TRACE_APPENDIX` in src/server/w3h/mod.rs.
APPENDIX = '# --- appendix: teardown (not digested) ---'


def digested(text):
    """The part of a trace file that is compared (before the appendix)."""
    head, marker, _appendix = text.partition(f'\n{APPENDIX}\n')
    return f'{head}\n' if marker else text


def load(directory):
    cases = defaultdict(list)
    for path in sorted(Path(directory).glob('*.trace')):
        case, _, _pid = path.stem.rpartition('-')
        if case:
            cases[case].append((path.name, digested(path.read_text())))
    return cases


def first_divergence(left, right):
    """The first removed and added lines of the diff, e.g. `- a | + b`."""
    removed = added = None
    for line in difflib.unified_diff(left.splitlines(), right.splitlines(),
                                     lineterm='', n=0):
        if line.startswith(('---', '+++')):
            continue
        if line.startswith('-') and removed is None:
            removed = line
        elif line.startswith('+') and added is None:
            added = line
        if removed is not None and added is not None:
            break
    if removed is None and added is None:
        return '(traces differ only in trailing whitespace)'
    return ' | '.join(part for part in (removed, added) if part is not None)


def check(directory, runs, required, strict_traces=False):
    """Trace presence and shim checks (blocking) and the distinct-trace
    report (blocking only with `strict_traces`)."""
    problems = []
    cases = load(directory)
    if not cases:
        problems.append(f'no traces in {directory}: nothing was checked')
    for case in required:
        if case not in cases:
            problems.append(f'{case}: no trace written')
    for case, traces in sorted(cases.items()):
        digests = {hashlib.blake2b(text.encode()).hexdigest() for _, text in traces}
        if len(traces) != runs:
            problems.append(f'{case}: {len(traces)} traces, expected {runs}')
        if any('entropy=controlled' not in text for _, text in traces):
            problems.append(f'{case}: entropy was not controlled (shim missing)')
        if len(digests) == 1:
            print(f'W3H-TRACES {case}: {len(traces)} runs, 1 distinct trace')
            continue
        base_name, base = traces[0]
        divergence = next(
            (f'{base_name} vs {name}: {first_divergence(base, text)}'
             for name, text in traces[1:] if text != base),
            '')
        line = (f'{case}: {len(traces)} runs, {len(digests)} distinct traces; '
                f'first divergence {divergence}')
        print(f'W3H-TRACES {line}')
        if strict_traces:
            problems.append(line)
    return problems


VERDICT_STAGES = {
    'RED': ('setup_done', 'evidence', 'request_delivered', 'cause', 'final'),
    'GREEN': ('setup_done', 'evidence', 'request_delivered', 'final'),
}


def incomplete(receipt, verdict):
    """Why `receipt` is not a complete `verdict` receipt, or None."""
    if verdict not in VERDICT_STAGES:
        return None
    stages = receipt.get('stages', [])
    names = {stage.get('stage') for stage in stages}
    missing = sorted(set(VERDICT_STAGES[verdict]) - names)
    if missing:
        return f'{verdict} receipt lacks stages {missing}'
    for stage in stages:
        kind = stage.get('stage')
        if kind in ('evidence', 'request_delivered', 'cause') and stage.get('ok') is not True:
            label = stage.get('name') or stage.get('expected')
            return f'{verdict} receipt has a false {kind} stage {label!r}'
    finals = [stage.get('passed') for stage in stages if stage.get('stage') == 'final']
    if finals[-1] is not (verdict == 'GREEN'):
        return f'{verdict} receipt has final passed={finals[-1]}'
    return None


def check_receipts(directory, runs, expectations):
    problems = []
    receipts = defaultdict(list)
    for path in sorted(Path(directory).glob('*.receipt.json')):
        case, _, _pid = path.name[:-len('.receipt.json')].rpartition('-')
        try:
            receipts[case].append(json.loads(path.read_text()))
        except json.JSONDecodeError as error:
            problems.append(f'{path.name}: unreadable receipt ({error})')
    for expectation in expectations:
        case, _, verdict = expectation.partition('=')
        found = receipts.get(case, [])
        if len(found) != runs:
            problems.append(f'{case}: {len(found)} receipts, expected {runs}')
        verdicts = sorted({str(receipt.get('verdict')) for receipt in found})
        if len(verdicts) > 1:
            problems.append(f'{case}: verdicts differ across reruns: {verdicts}')
        for receipt in found:
            if receipt.get('schema') != 'w3h.receipt/1':
                problems.append(f'{case}: unknown receipt schema {receipt.get("schema")!r}')
                break
            if receipt.get('verdict') != verdict:
                problems.append(f'{case}: verdict {receipt.get("verdict")}, expected {verdict}')
                break
            why = incomplete(receipt, verdict)
            if why:
                problems.append(f'{case}: {why}')
                break
        else:
            if found and len(found) == runs:
                print(f'W3H-VERDICT {case}: {len(found)} complete receipts, all {verdict}')
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    parser.add_argument('--runs', type=int, required=True)
    parser.add_argument('--require', action='append', default=[])
    parser.add_argument('--expect', action='append', default=[],
                        help='CASE=RED|GREEN|INFRA, checked against receipts')
    parser.add_argument('--strict-traces', action='store_true',
                        help='also fail when a case has more than one distinct trace')
    args = parser.parse_args(argv)
    problems = check(args.directory, args.runs, args.require, args.strict_traces)
    problems += check_receipts(args.directory, args.runs, args.expect)
    for problem in problems:
        print(f'W3H-GATE FAIL {problem}', file=sys.stderr)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
