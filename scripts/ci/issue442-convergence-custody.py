#!/usr/bin/env python3
"""Closed #442 phase custody; nextest terminal accounting remains separate."""
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('isolation_custody', Path(__file__).with_name('isolation-custody-collect.py'))
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
SELECTOR = 'asymmetric_capability_convergence_tests::asymmetric_signed_capability_convergence_over_relay'
PRE = ('relay_inbox_ready', 'relay_watch_held', 'sender_has_relay_base', 'sender_has_relay_extension', 'relay_has_sender_extension', 'relay_has_sender_v2_baseline')
COUNTS = ('delivery_count', 'extra_count', 'unrelated_count', 'window_ms', 'forwarded_before', 'forwarded_after', 'refused_before', 'refused_after')
PHASES = ('legacy', 'bound', 'downgrade')
REFUSALS = ('bad_signature', 'inner_digest_mismatch', 'missing_inner_digest', 'stale', 'policy_disabled', 'not_a_contact', 'blocked', 'rate_limited', 'bandwidth_exceeded')
CODES = ('INPUT_MISSING', 'INPUT_UNSAFE', 'INPUT_OVERSIZE', 'INPUT_SCHEMA', 'CORRELATION', 'BINARY_BINDING', 'PHASE_INCOMPLETE', 'PHASE_ASSERTION', 'OUTPUT_UNSAFE', 'CUSTODY_INCOMPLETE', 'TEST_NOT_SUCCESS', 'PREPARE_MISSING')


class Rejected(Exception):
    def __init__(self, code):
        assert code in CODES
        self.code = code
        super().__init__(code)


def require(ok, code='INPUT_SCHEMA'):
    if not ok:
        raise Rejected(code)


def keys(value, names):
    require(type(value) is dict and set(value) == set(names))
    return value


def hx(value, size):
    require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None)
    return value


def boolean(value, nullable=False):
    require((nullable and value is None) or type(value) is bool)


def number(value, nullable=False, maximum=(1 << 64) - 1):
    require((nullable and value is None) or (type(value) is int and 0 <= value <= maximum))


def safe_directory(path):
    # Check every existing component, including the input root's ancestors.
    for part in [*reversed(path.absolute().parents), path.absolute()]:
        try:
            info = part.lstat()
        except OSError as error:
            raise Rejected('INPUT_MISSING') from error
        require(stat.S_ISDIR(info.st_mode), 'INPUT_UNSAFE')


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def read_json(path, limit):
    safe_directory(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            require(stat.S_ISREG(info.st_mode), 'INPUT_UNSAFE')
            require(info.st_size <= limit, 'INPUT_OVERSIZE')
            raw = source.read(limit + 1)
        require(len(raw) <= limit, 'INPUT_OVERSIZE')
        return json.loads(raw, object_pairs_hook=no_duplicates)
    except Rejected:
        raise
    except FileNotFoundError as error:
        raise Rejected('INPUT_MISSING') from error
    except OSError as error:
        raise Rejected('INPUT_UNSAFE') from error
    except (UnicodeError, ValueError) as error:
        raise Rejected('INPUT_SCHEMA') from error


def descriptor(value):
    keys(value, ('schema', 'run_nonce', 'source_head', 'source_tree', 'selector'))
    require(value['schema'] == 'x0x.issue442-descriptor/1' and value['selector'] == SELECTOR)
    hx(value['run_nonce'], 32)
    hx(value['source_head'], 40)
    hx(value['source_tree'], 40)
    return value


def prepare(workspace, event_sha, source):
    require(len(source) == 2 and source[0] == event_sha, 'CORRELATION')
    value = descriptor(dict(schema='x0x.issue442-descriptor/1', run_nonce=secrets.token_hex(16), source_head=source[0], source_tree=source[1], selector=SELECTOR))
    safe_directory(workspace)
    parent = workspace / 'ci-evidence'
    try:
        parent.mkdir(mode=0o700)
    except FileExistsError:
        safe_directory(parent)
    safe_directory(parent)
    root = parent / 'issue442'
    try:
        root.mkdir(mode=0o700)
        fd = os.open(root / 'descriptor.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as output:
            output.write(json.dumps(value) + '\n')
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        raise Rejected('OUTPUT_UNSAFE') from error
    return value['run_nonce']


def service(value):
    keys(value, ('overflow', 'poisoned', 'events'))
    for name in ('overflow', 'poisoned'):
        boolean(value[name])
    require(type(value['events']) is list and len(value['events']) <= 16)
    for event in value['events']:
        require(type(event) is dict)
        kind = event.get('kind')
        if kind == 'enqueue':
            keys(event, ('kind', 'requester', 'carrier', 'payload_sha256', 'accepted'))
            hx(event['requester'], 64)
            hx(event['payload_sha256'], 64)
            require(event['carrier'] in ('warm', 'critical'))
            boolean(event['accepted'])
        else:
            keys(event, ('kind',))
            require(kind in ('consumed', 'pending_skip'))


def relay(value):
    keys(value, ('overflow', 'poisoned', 'decode_failed', 'events'))
    for name in ('overflow', 'poisoned', 'decode_failed'):
        boolean(value[name])
    require(type(value['events']) is list and len(value['events']) <= 16)
    for event in value['events']:
        keys(event, ('request_id', 'sender', 'destination', 'digest_present', 'hop', 'prefix', 'sent_wire', 'classification'))
        hx(event['request_id'], 32)
        for name in ('sender', 'destination', 'hop', 'prefix'):
            hx(event[name], 64)
        boolean(event['digest_present'])
        if event['sent_wire'] is not None:
            wire = keys(event['sent_wire'], ('length', 'sha256'))
            number(wire['length'], maximum=(1 << 32) - 1)
            hx(wire['sha256'], 64)
        # Classification is observed before later revocation, forwarding, or delivery.
        # Actual forward counters and D's decrypted receive counts are separate evidence.
        classification = event['classification']
        if classification is not None:
            require(type(classification) is dict)
            kind = classification.get('kind')
            if kind == 'forward':
                keys(classification, ('kind', 'destination'))
                hx(classification['destination'], 64)
            elif kind == 'refuse':
                keys(classification, ('kind', 'reason'))
                require(classification['reason'] in REFUSALS)
            else:
                keys(classification, ('kind',))
                require(kind == 'deliver_locally')


def phase_schema(value):
    keys(value, ('schema', 'run_nonce', 'source_head', 'source_tree', 'selector', 'binary_sha256', 'status', 'checkpoint', 'topology', 'preconditions', 'phases', 'service_observation', 'relay_observations'))
    require(value['schema'] == 'x0x.issue442-phases/1' and value['selector'] == SELECTOR)
    for name, length in [('run_nonce', 32), ('source_head', 40), ('source_tree', 40), ('binary_sha256', 64)]:
        hx(value[name], length)
    require(value['status'] in ('started', 'partial', 'completed'))
    require(value['checkpoint'] in ('entry', 'setup', 'held_request', *PHASES, 'cleanup'))
    if value['topology'] is not None:
        for node in keys(value['topology'], ('s', 'r', 'd')).values():
            for identifier in keys(node, ('agent_id', 'machine_id')).values():
                hx(identifier, 64)
    for flag in keys(value['preconditions'], PRE).values():
        boolean(flag, True)
    seen_ids = []
    absent = False
    keys(value['phases'], PHASES)
    for name in PHASES:
        phase = value['phases'][name]
        if phase is None:
            absent = True
            continue
        require(not absent)
        keys(phase, ('request_id', 'outcome', *COUNTS, 'extension_present', 'baseline_present'))
        hx(phase['request_id'], 32)
        require(phase['request_id'] not in seen_ids)
        seen_ids.append(phase['request_id'])
        require(phase['outcome'] in ('entered', 'observed'))
        for name in COUNTS:
            number(phase[name], True)
        require(phase['window_ms'] in (None, 300))
        boolean(phase['extension_present'], True)
        boolean(phase['baseline_present'], True)
    if value['service_observation'] is not None:
        service(value['service_observation'])
    for observer in keys(value['relay_observations'], ('s', 'r', 'd')).values():
        if observer is not None:
            relay(observer)
    return value


def completed(value):
    require(value['status'] == 'completed' and value['checkpoint'] == 'cleanup', 'PHASE_INCOMPLETE')
    require(value['topology'] is not None, 'PHASE_ASSERTION')
    topology = value['topology']
    require(len({v['agent_id'] for v in topology.values()}) == 3 and len({v['machine_id'] for v in topology.values()}) == 3, 'PHASE_ASSERTION')
    require(value['preconditions'] == dict(zip(PRE, (True, True, True, False, True, False))), 'PHASE_ASSERTION')
    svc = value['service_observation']
    require(svc is not None and not svc['overflow'] and not svc['poisoned'], 'PHASE_ASSERTION')
    enqueues = [e for e in svc['events'] if e['kind'] == 'enqueue']
    require(len(enqueues) == 1 and enqueues[0]['requester'] == topology['s']['agent_id'] and enqueues[0]['carrier'] == 'critical' and enqueues[0]['accepted'], 'PHASE_ASSERTION')
    kinds = [e['kind'] for e in svc['events']]
    require(kinds.count('consumed') == 1 and 'pending_skip' in kinds[kinds.index('consumed') + 1:], 'PHASE_ASSERTION')
    observers = value['relay_observations']
    for observer in observers.values():
        require(observer is not None and not any(observer[k] for k in ('overflow', 'poisoned', 'decode_failed')), 'PHASE_ASSERTION')
    require([len(observers[n]['events']) for n in ('s', 'r', 'd')] == [2, 3, 0], 'PHASE_ASSERTION')
    previous = None
    for name in PHASES:
        phase = value['phases'][name]
        require(phase is not None and phase['outcome'] == 'observed', 'PHASE_ASSERTION')
        require(all(phase[n] is not None for n in COUNTS), 'PHASE_ASSERTION')
        positive = name != 'downgrade'
        require((phase['delivery_count'], phase['extra_count'], phase['unrelated_count'], phase['window_ms']) == (int(positive), 0, 0, 300), 'PHASE_ASSERTION')
        require(phase['forwarded_after'] == phase['forwarded_before'] + int(positive) and phase['refused_after'] == phase['refused_before'] + int(not positive), 'PHASE_ASSERTION')
        if previous is not None:
            require((phase['forwarded_before'], phase['refused_before']) == previous, 'PHASE_ASSERTION')
        previous = (phase['forwarded_after'], phase['refused_after'])
        require(phase['extension_present'] is (name != 'legacy') and phase['baseline_present'] is (name != 'legacy'), 'PHASE_ASSERTION')
        received = [e for e in observers['r']['events'] if e['request_id'] == phase['request_id']]
        require(len(received) == 1, 'PHASE_ASSERTION')
        event = received[0]
        require(event['sender'] == topology['s']['agent_id'] and event['destination'] == topology['d']['agent_id'] and event['hop'] == topology['s']['machine_id'] and event['prefix'] == topology['s']['agent_id'] and event['sent_wire'] is None and event['digest_present'] is (name == 'bound'), 'PHASE_ASSERTION')
        expected = dict(kind='forward', destination=topology['d']['agent_id']) if positive else dict(kind='refuse', reason='missing_inner_digest')
        require(event['classification'] == expected, 'PHASE_ASSERTION')
        if positive:
            sent = [e for e in observers['s']['events'] if e['request_id'] == phase['request_id']]
            require(len(sent) == 1, 'PHASE_ASSERTION')
            event = sent[0]
            require(event['sender'] == topology['s']['agent_id'] and event['destination'] == topology['d']['agent_id'] and event['hop'] == topology['r']['agent_id'] and event['prefix'] == topology['s']['agent_id'] and event['digest_present'] is (name == 'bound') and event['classification'] is None and event['sent_wire'] is not None and event['sent_wire']['length'] > 0, 'PHASE_ASSERTION')


def load_phases(root, nonce, custody, event_sha):
    safe_directory(root)
    require(set(p.name for p in root.iterdir()) <= {'descriptor.json', 'claim.json', 'phases.json', 'phases.tmp'}, 'INPUT_UNSAFE')
    desc = descriptor(read_json(root / 'descriptor.json', 1024))
    claim = keys(read_json(root / 'claim.json', 1024), ('schema', 'run_nonce', 'selector', 'binary_sha256'))
    require(claim['schema'] == 'x0x.issue442-claim/1' and claim['selector'] == SELECTOR)
    hx(claim['run_nonce'], 32)
    hx(claim['binary_sha256'], 64)
    value = phase_schema(read_json(root / 'phases.json', 64 * 1024))
    require(nonce == desc['run_nonce'] == claim['run_nonce'] == value['run_nonce'], 'CORRELATION')
    require(value['binary_sha256'] == claim['binary_sha256'], 'CORRELATION')
    require(len(custody['build_custody']) == 1, 'BINARY_BINDING')
    build = custody['build_custody'][0]
    require(desc['source_head'] == value['source_head'] == build['source_head'] == event_sha and desc['source_tree'] == value['source_tree'] == build['source_tree'], 'CORRELATION')
    matches = [name for name in build['target_binaries'] if build['inputs'][name] == value['binary_sha256']]
    require(len(matches) == 1, 'BINARY_BINDING')
    return value


def compose(root, nonce, custody, expect, event_sha):
    output = dict(schema='x0x.issue442-custody/1', expected_nonce=None, phase_status='absent', phases=None, custody=custody, errors=[], valid=False)
    try:
        require(nonce is not None and nonce != '', 'PREPARE_MISSING')
        output['expected_nonce'] = hx(nonce, 32)
        value = load_phases(root, nonce, custody, event_sha)
        output['phases'] = value
        output['phase_status'] = 'completed' if value['status'] == 'completed' else 'partial'
        if value['status'] == 'completed' or expect == 'success':
            completed(value)
    except Rejected as error:
        if output['phases'] is None and error.code not in ('INPUT_MISSING', 'PREPARE_MISSING'):
            output['phase_status'] = 'rejected'
        output['errors'].append(dict(stage='phase', code=error.code))
    if not custody['valid']:
        output['errors'].append(dict(stage='custody', code='CUSTODY_INCOMPLETE'))
    if expect != 'success':
        output['errors'].append(dict(stage='test', code='TEST_NOT_SUCCESS'))
    output['valid'] = not output['errors']
    return output


def emit(name, value):
    if os.environ.get('GITHUB_OUTPUT'):
        with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='ascii') as output:
            output.write(f'{name}={value}\n')


def main():
    require(len(sys.argv) == 2 and sys.argv[1] in ('prepare', 'collect'))
    workspace = Path(os.environ['GITHUB_WORKSPACE'])
    event_sha = hx(os.environ['GITHUB_SHA'], 40)
    if sys.argv[1] == 'prepare':
        source = subprocess.check_output(['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], cwd=workspace, text=True).splitlines()
        nonce = prepare(workspace, event_sha, source)
        emit('run_nonce', nonce)
        emit('prepared', 'true')
        return 0
    expect = os.environ.get('X0X_CUSTODY_EXPECT', '')
    require(expect in ('success', 'failure', 'cancelled', 'skipped'))
    runner_temp = Path(os.environ['RUNNER_TEMP'])
    safe_directory(runner_temp)
    output_dir = runner_temp / 'x0x-issue442-receipt'
    BASE.exclusive_output(output_dir)
    custody = BASE.collect(runner_temp, expect, event_sha, workspace, ['acceptance'], 'x0x', 1)
    result = compose(workspace / 'ci-evidence/issue442', os.environ.get('X0X_ISSUE442_NONCE'), custody, expect, event_sha)
    BASE.assert_no_leak(result)
    BASE.write_receipt(output_dir, result)
    BASE.mark_upload_eligible()
    print(json.dumps(dict(valid=result['valid'], phase_status=result['phase_status'], errors=result['errors'])))
    return int(expect == 'success' and not result['valid'])


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Rejected, BASE.Rejected) as error:
        print('issue442 custody: ' + error.code, file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('issue442 custody: INPUT_SCHEMA', file=sys.stderr)
        sys.exit(1)
