#!/usr/bin/env python3
"""Closed per-test accounting for the disposable #574 suite diagnostic.

Never interpret JSON suite fragments as final binary results. No report-derived
strings are exported: identities are hashes of discovery tuples, output is only
parsed after the complete JUnit binary/test boundary has been checked.
"""
import collections
import datetime
import hashlib
import json
import math
import re
import xml.etree.ElementTree as ET

from lifecycle574_trace import trace_rows

TEST = 'server::routes::named_groups::tests::hs_f2_membership_cluster::integration_treekem_home_rename_restart_single_announce_end_to_end'
TARGET = ('x0x', 'x0x', 'lib', TEST)
MAX_CASES = 20000
MAX_BYTES = 64 * 1024 * 1024


class Invalid(ValueError):
    """Exception text is a closed category, never product output."""


def require(condition, code='REPORT_INVALID'):
    if not condition:
        raise Invalid(code)


def integer(value, maximum=MAX_CASES):
    require(type(value) is int and 0 <= value <= maximum)
    return value


def number(value, maximum=1900):
    require(type(value) in (int, float) and math.isfinite(value) and 0 <= value)
    require(value <= maximum, 'NUMBER_BOUND')
    return value


def identifier(identity):
    return hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()


def manifest(listing):
    require(isinstance(listing, dict) and isinstance(listing.get('rust-suites'), dict))
    known, names, binaries = {}, {}, {}
    for bid, suite in listing['rust-suites'].items():
        require(isinstance(bid, str) and 0 < len(bid) < 1024)
        require(isinstance(suite, dict))
        package, binary, kind = (suite[key] for key in ('package-name', 'binary-name', 'kind'))
        require(all(isinstance(x, str) and 0 < len(x) < 1024 for x in (package, binary, kind)))
        require(kind in ('lib', 'bin', 'test', 'bench', 'example', 'proc-macro'))
        require(suite['status'] in ('listed', 'skipped'))
        binaries[bid] = (package, binary, kind)
        cases = suite.get('testcases', {})
        require(isinstance(cases, dict))
        require(suite['status'] == 'listed' or not cases)
        for name, case in cases.items():
            require(isinstance(name, str) and 0 < len(name) <= 4096)
            require(type(case['ignored']) is bool and case['kind'] == 'test')
            match = case['filter-match']
            require(match['status'] in ('matches', 'mismatch'))
            selected = match['status'] == 'matches'
            reason = None if selected else match.get('reason')
            require(reason in (None, 'ignored', 'expression', 'default-filter', 'partition', 'platform'))
            require(not selected or not case['ignored'], 'IGNORED_SELECTED')
            identity = (package, binary, kind, name)
            key = (bid, name)
            qualified = package + '::' + binary + '$' + name
            require(key not in known and qualified not in names, 'IDENTITY_AMBIGUOUS')
            known[key] = dict(identity=identity, id=identifier(identity), selected=selected,
                              ignored=case['ignored'], reason=reason)
            names[qualified] = key
            require(len(known) <= MAX_CASES)
    require(known, 'EMPTY_DISCOVERY')
    require(integer(listing['test-count']) == len(known), 'DISCOVERY_COUNT')
    require(len({v['id'] for v in known.values()}) == len(known), 'IDENTITY_AMBIGUOUS')
    return known, names, binaries


def interrupted_prefix(listing, json_text):
    """Closed prefix observations only; never complete accounting or unrun proof."""
    require(isinstance(json_text, str) and len(json_text.encode()) <= MAX_BYTES)
    known, names, _ = manifest(listing)
    starts, terminals, truncated = set(), {}, False
    lines = json_text.splitlines()
    for index, line in enumerate(lines):
        if not line.strip(): continue
        try:
            event = json.loads(line)
        except ValueError:
            require(index == len(lines)-1, 'PARTIAL_INTERIOR_TRUNCATION')
            truncated = True
            break
        require(isinstance(event, dict))
        if event.get('type') == 'suite': continue
        require(event.get('type') == 'test' and event.get('name') in names, 'PARTIAL_IDENTITY')
        key = names[event['name']]
        state = event.get('event')
        require(state in ('started', 'ok', 'failed', 'ignored'))
        if not known[key]['selected']:
            require(known[key]['reason'] == 'ignored' and state in ('started', 'ignored'))
            continue
        if state == 'started':
            require(key not in starts, 'PARTIAL_DUPLICATE')
            starts.add(key)
        else:
            require(state in ('ok', 'failed') and key in starts and key not in terminals, 'PARTIAL_SEQUENCE')
            terminals[key] = state
    rows = []
    for key, value in sorted(known.items(), key=lambda item: item[1]['id']):
        if not value['selected']: continue
        row = {'id': value['id'], 'state': 'terminal_observed' if key in terminals else
               'started_without_terminal' if key in starts else 'unobserved_in_prefix'}
        if key in terminals: row['terminal_status'] = terminals[key]
        rows.append(row)
    return {'accounting_valid': False, 'prefix_only': True, 'truncated_last_line': truncated,
            'observed_starts': len(starts), 'observed_terminals': len(terminals),
            'started_without_terminal': len(starts-set(terminals)), 'tests': rows,
            'general_acceptance': False}


def account(listing, json_text, xml_bytes, process_exit, target=TARGET):
    """Return closed facts or reject all accounting. Raw reports stay private."""
    require(isinstance(json_text, str) and len(json_text.encode()) <= MAX_BYTES)
    require(isinstance(xml_bytes, bytes) and len(xml_bytes) <= MAX_BYTES)
    require(b'<!DOCTYPE' not in xml_bytes and b'<!ENTITY' not in xml_bytes, 'XML_UNSAFE')
    require(process_exit in (0, 100) and type(process_exit) is int, 'PROCESS_INTERRUPTED')
    known, names, binaries = manifest(listing)
    selected = {k for k, v in known.items() if v['selected']}
    target_keys = [k for k, v in known.items() if v['identity'] == target]
    require(len(target_keys) == 1 and target_keys[0] in selected, 'TARGET_SELECTION')
    target_key = target_keys[0]
    require(selected, 'EMPTY_SELECTION')
    starts, terminals, terminal_order = collections.Counter(), {}, []
    fragments = 0
    ignored_terminals = set()
    for line in json_text.splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        require(isinstance(e, dict))
        if e.get('type') == 'suite':
            require(e.get('event') in ('started', 'ok', 'failed'))
            meta = e.get('nextest')
            require(isinstance(meta, dict) and set(meta) == {'crate', 'test_binary', 'kind'})
            require((meta['crate'], meta['test_binary'], meta['kind']) in binaries.values())
            # The exact producer can emit multiple fragments per binary.
            fragments += 1
            require(fragments <= MAX_CASES * 4)
            continue
        require(e.get('type') == 'test' and e.get('name') in names, 'JSON_IDENTITY')
        key = names[e['name']]
        event = e.get('event')
        require(event in ('started', 'ignored', 'ok', 'failed'), 'JSON_EVENT')
        if event == 'started':
            require(key in selected or known[key]['reason'] == 'ignored', 'JSON_SELECTION')
            starts[key] += 1
            require(starts[key] == 1, 'DUPLICATE_START')
        elif event == 'ignored':
            require(known[key]['reason'] == 'ignored' and starts[key] == 1 and key not in ignored_terminals, 'IGNORED_EVENT')
            ignored_terminals.add(key)
        else:
            require(key in selected and starts[key] == 1 and key not in terminals, 'TERMINAL_SEQUENCE')
            number(e.get('exec_time'))
            require(e.get('reason') in (None, 'time limit exceeded'), 'RETRY_OR_REASON')
            require(e.get('reason') is None or event == 'failed', 'REASON_STATUS')
            terminals[key] = (event, e['exec_time'], e.get('reason'))
            terminal_order.append(key)
    # Ordinary ignored starts may never receive a flushed ignored terminal.
    require(all(starts[k] == 0 or k in terminals for k in selected), 'MISSING_TERMINAL')
    require(terminals, 'NO_EXECUTION')
    root = ET.fromstring(xml_bytes)
    require(root.tag == 'testsuites', 'XML_ROOT')
    start_time = datetime.datetime.fromisoformat(root.attrib['timestamp'])
    require(start_time.tzinfo is not None)
    number(float(root.attrib['time']))
    seen, seen_suites, intervals, failure_kinds = {}, set(), {}, {}
    for suite in root:
        require(suite.tag == 'testsuite', 'XML_SCHEMA')
        bid = suite.attrib['name']
        require(bid in binaries and bid not in seen_suites, 'XML_BINARY')
        seen_suites.add(bid)
        children = list(suite)
        require(all(c.tag == 'testcase' for c in children), 'XML_SCHEMA')
        for case in children:
            key = (bid, case.attrib['name'])
            require(case.attrib['classname'] == bid and key in known and key not in seen, 'XML_IDENTITY')
            require(all(c.tag in ('skipped', 'failure', 'error', 'system-out', 'system-err') for c in case), 'XML_SCHEMA')
            require(all(len(case.findall(tag)) <= 1 for tag in ('skipped', 'failure', 'error', 'system-out', 'system-err')))
            outcome = [tag for tag in ('skipped', 'failure', 'error') if case.find(tag) is not None]
            require(len(outcome) <= 1)
            status = 'skipped' if outcome == ['skipped'] else 'failed' if outcome else 'ok'
            require((status != 'skipped') == (key in selected), 'XML_SELECTION')
            if status == 'skipped':
                require(float(case.attrib['time']) == 0 and 'timestamp' not in case.attrib)
                require(case.find('system-out') is None and case.find('system-err') is None)
            else:
                require(key in terminals and terminals[key][0] == status, 'STATUS_DISAGREEMENT')
                duration = number(float(case.attrib['time']))
                require(abs(duration - terminals[key][1]) <= 0.002, 'DURATION_DISAGREEMENT')
                timestamp = datetime.datetime.fromisoformat(case.attrib['timestamp'])
                require(timestamp.tzinfo is not None)
                relative = (timestamp - start_time).total_seconds()
                require(-0.002 <= relative <= 1900)
                intervals[key] = (round(relative * 1000), round(duration * 1000))
            if status == 'failed':
                detail = case.find(outcome[0]).attrib.get('type')
                if detail == 'test timeout':
                    category = 'timeout'
                elif detail in ('test abort', 'test abort (leaked handles)'):
                    category = 'abort'
                elif detail == 'execution failure':
                    category = 'execution_error'
                elif isinstance(detail, str) and re.fullmatch(r'test failure with exit code -?[0-9]{1,10}( \(leaked handles\))?', detail):
                    category = 'exit_failure'
                elif detail == 'test exited with code 0, but leaked handles so was marked failed':
                    category = 'leak_failure'
                else:
                    raise Invalid('FAILURE_KIND_UNPROVEN')
                require((category == 'timeout') == (terminals[key][2] == 'time limit exceeded'), 'TIMEOUT_DISAGREEMENT')
                failure_kinds[key] = category
            seen[key] = (status, case, outcome)
        for field, wanted in [('tests', len(children)),
                              ('skipped', sum(seen[(bid, c.attrib['name'])][0] == 'skipped' for c in children)),
                              ('failures', sum(c.find('failure') is not None for c in children)),
                              ('errors', sum(c.find('error') is not None for c in children))]:
            require(int(suite.attrib.get(field, '0')) == wanted, 'XML_COUNTS')
    require({k for k, (v, _, _) in seen.items() if v != 'skipped'} == set(terminals), 'MISSING_XML_CASE')
    # report-skipped=all: all cases discovered but not selected are accounted.
    require({k for k, v in known.items() if not v['selected']} <= set(seen), 'MISSING_SKIPPED')
    for field, wanted in [('tests', len(seen)), ('skipped', sum(v[0] == 'skipped' for v in seen.values())),
                          ('failures', sum(v[2] == ['failure'] for v in seen.values())),
                          ('errors', sum(v[2] == ['error'] for v in seen.values()))]:
        require(int(root.attrib.get(field, '0')) == wanted, 'XML_COUNTS')
    failed = {k for k, v in terminals.items() if v[0] == 'failed'}
    unrun = selected - set(terminals)
    require((process_exit == 0) == (not failed and not unrun), 'EXIT_DISAGREEMENT')
    require(not unrun or failed, 'UNRUN_WITHOUT_FAILURE')
    target_status = 'unrun' if target_key in unrun else terminals[target_key][0]
    trace, trace_state = None, 'unrun'
    if target_key in seen:
        case = seen[target_key][1]
        out, err = case.findtext('system-out'), case.findtext('system-err')
        # Only the exact combined-capture contract is admitted by this route.
        require(out is not None and err == '(stdout and stderr are combined)', 'OUTPUT_BOUNDARY')
        if any(line.strip().startswith('DIAG lifecycle574') for line in out.splitlines()):
            trace = trace_rows(out)
            require(not any(r['event'] == 'snapshot' for r in trace['rows']), 'HEALTH_QUERY_ROW')
            trace_state = 'gaps' if trace['evidence_gaps'] else 'complete'
        else:
            trace_state = 'unavailable'
    rows = []
    for key, v in sorted(known.items(), key=lambda item: item[1]['id']):
        state = terminals[key][0] if key in terminals else 'unrun' if key in selected else 'ignored' if v['reason'] == 'ignored' else 'excluded'
        row = {'id': v['id'], 'state': state}
        if key in failure_kinds:
            row['failure_kind'] = failure_kinds[key]
        if key in intervals:
            row.update(start_ms=intervals[key][0], duration_ms=intervals[key][1])
        rows.append(row)
    overlaps = []
    if target_key in intervals:
        a, d = intervals[target_key]
        overlaps = [known[k]['id'] for k, (b, e) in intervals.items()
                    if k != target_key and min(a+d, b+e) - max(a, b) > 2]
    return {'accounting_valid': True, 'discovered': len(known), 'selected': len(selected),
            'executed': len(terminals), 'passed': len(terminals)-len(failed), 'failed': len(failed),
            'failure_kinds': dict(sorted(collections.Counter(failure_kinds.values()).items())),
            'unrun': len(unrun), 'ignored': sum(v['reason'] == 'ignored' for v in known.values()),
            'excluded': sum(not v['selected'] and v['reason'] != 'ignored' for v in known.values()),
            'binary_count': len(binaries), 'undiscovered_binary_count': sum(s['status'] == 'skipped' for s in listing['rust-suites'].values()),
            'manifest_sha256': identifier(sorted((k, v['identity'], v['selected'], v['reason']) for k, v in known.items())),
            'tests': rows, 'process_exit': process_exit, 'target_id': known[target_key]['id'],
            'target_status': target_status, 'target_trace_state': trace_state, 'trace': trace,
            'target_terminal_position': terminal_order.index(target_key)+1 if target_key in terminal_order else None,
            'overlap_ids': sorted(overlaps), 'timing': 'rounded_wall_clock_intervals_not_monotonic',
            'synthetic_ignored_starts': sum(starts[k] for k in starts if k not in selected),
            'general_acceptance': False}
