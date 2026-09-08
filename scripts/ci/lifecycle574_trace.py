"""Exact R3 lifecycle projection copied from reviewed 05459ab; no network queries."""
import json
import re

REASONS = 'Superseded ReaderExit PeerShutdown Banned LifecycleCleanup NoReader LivenessTimeout ApplicationClosed ConnectionClosed TimedOut Reset TransportError LocallyClosed VersionMismatch CidsExhausted Unknown'.split()
MARKERS = {'before_old_shutdown', 'before_new_dial', 'reconnected', 'readiness_returned', 'collector_join_error'}


def require(condition):
    if not condition:
        raise ValueError("TRACE_INVALID")


def trace_rows(text):
    rows, summary = [], None
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith('DIAG lifecycle574'):
            continue
        require(summary is None)
        m = re.fullmatch(r'DIAG lifecycle574 seq=(\d+) elapsed_us=(\d+) side=(Owner|Joiner) (.+)', line)
        if m:
            seq, elapsed, side, detail = m.groups()
            require(len(rows) < 256 and int(seq) == len(rows) + 1)
            require(int(elapsed) <= 30 * 60 * 1_000_000)
            require(not rows or int(elapsed) >= rows[-1]['elapsed_us'])
            row = {'sequence': int(seq), 'elapsed_us': int(elapsed), 'side': side}
            if detail.startswith('lifecycle='):
                event = detail.removeprefix('lifecycle=')
                fields = re.fullmatch(r'(Established|ReaderExited) \{ generation: (\d+) \}', event)
                replaced = re.fullmatch(r'Replaced \{ old_generation: (\d+), new_generation: (\d+) \}', event)
                closed = re.fullmatch(r'(Closing|Closed) \{ generation: (\d+), reason: (' + '|'.join(REASONS) + r') \}', event)
                require(fields or replaced or closed)
                if fields: row.update(event=fields[1], generation=int(fields[2]))
                if replaced: row.update(event='Replaced', old_generation=int(replaced[1]), new_generation=int(replaced[2]))
                if closed: row.update(event=closed[1], generation=int(closed[2]), reason=closed[3])
            elif detail in {'stream_closed', 'stream_unavailable', 'capture_event_limit', 'capture_deadline'}:
                row['event'] = detail
            elif re.fullmatch(r'lagged=\d+', detail):
                row.update(event='lagged', count=int(detail.split('=')[1]))
            elif re.fullmatch(r'marker=[a-z_]+', detail):
                marker = detail.split('=')[1]; require(marker in MARKERS)
                row.update(event='marker', marker=marker)
            elif re.fullmatch(r'publish_attempted=(None|Some\(\d+\))', detail):
                val = detail.split('=')[1]
                row.update(event='publish', attempted=None if val == 'None' else int(val[5:-1]))
            elif detail == 'transport=unobserved send_ready=unobserved admission=unobserved':
                row.update(event='unobserved', transport='unobserved',
                           send_ready='unobserved', admission='unobserved')
            else:
                # Historical R2 evidence remains parseable. R3 never queries
                # connectivity; these values are not causally passive samples.
                snap = re.fullmatch(r'transport_send_ready=(None|Some\(\((true|false), (true|false)\)\)) admission=unavailable', detail)
                require(snap)
                row.update(event='snapshot', transport=None if snap[1] == 'None' else snap[2] == 'true',
                           send_ready=None if snap[1] == 'None' else snap[3] == 'true', admission='unavailable')
            require(all(type(v) is not int or 0 <= v < 2**64 for v in row.values()))
            rows.append(row)
            continue
        stop = re.fullmatch(r'DIAG lifecycle574 stop=(collectors_joined|abort_requested_on_drop) total=(\d+) overflow=(\d+) foreign=(\[\d+, \d+\]) lagged=(\[\d+, \d+\]) stream_closed=(\[(?:true|false), (?:true|false)\]) pending_at_stop=(\[\d+, \d+\]) collectors_dropped=(\[(?:true|false), (?:true|false)\]) acceptance=not_evaluated', line)
        require(stop)
        summary = dict(stop=stop[1], total=int(stop[2]), overflow=int(stop[3]),
                       foreign=json.loads(stop[4]), lagged=json.loads(stop[5]),
                       stream_closed=json.loads(stop[6]), pending_at_stop=json.loads(stop[7]),
                       collectors_dropped=json.loads(stop[8]))
        require(summary['total'] == len(rows) + summary['overflow'])
        for name in ('total', 'overflow', 'foreign', 'lagged', 'pending_at_stop'):
            values = summary[name] if isinstance(summary[name], list) else [summary[name]]
            require(all(type(v) is int and 0 <= v < 2**64 for v in values))
    require(summary is not None)
    gaps = (summary['overflow'] > 0 or any(summary['lagged']) or any(summary['pending_at_stop'])
            or summary['stop'] != 'collectors_joined' or not all(summary['collectors_dropped'])
            or any(r['event'] in {'stream_unavailable', 'capture_event_limit', 'capture_deadline'} for r in rows))
    return {'rows': rows, 'summary': summary, 'evidence_gaps': bool(gaps), 'general_acceptance': False}
