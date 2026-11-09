import collections
import importlib.util
import json
import math
import pathlib
import re
import statistics

directory = pathlib.Path('/tmp/araphor-callgrind')
report = json.loads((directory / 'wait-current-combined.json').read_text())
spec = importlib.util.spec_from_file_location(
    'summarize_cdc', 'crates/araphor-graph/examples/storage_poc/summarize_cdc.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
summary = module.summarize(report)
(directory / 'wait-current-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
pending = {}
events = []
for line in (directory / 'wait-current-strace.log').read_text().splitlines():
    match = re.fullmatch(r'(\d+)\s+(\d+\.\d+)\s+(.*)', line)
    assert match, line
    thread, timestamp, body = match.groups()
    timestamp = float(timestamp)
    if '<unfinished ...>' in body:
        assert thread not in pending
        pending[thread] = (timestamp, body.split('<unfinished ...>', 1)[0])
        continue
    if match := re.match(r'^<\.\.\. \w+ resumed>(.*)', body):
        timestamp, prefix = pending.pop(thread)
        body = prefix + match[1]
    if body.startswith(('+++', '---')):
        continue
    match = re.fullmatch(r'(write|writev|fsync|fdatasync|lseek|futex)\((.*?)\)\s+=\s+(.+?)\s+<(\d+\.\d+)>', body)
    assert match, body
    operation, arguments, returned, elapsed = match.groups()
    descriptor = re.match(r'^(\d+)<([^>]+)>', arguments)
    path = descriptor[2] if descriptor else None
    returned = int(returned.split()[0])
    events.append(dict(thread=thread, started_s=timestamp, elapsed_s=float(elapsed),
                       operation=operation, arguments=arguments, returned=returned,
                       path=path, descriptor=int(descriptor[1]) if descriptor else None))
assert not pending
events.sort(key=lambda event: event['started_s'])
main = events[0]['thread']


def percentiles(values):
    values = sorted(values)
    assert values
    return dict(samples=len(values), median=statistics.median(values) * 1000,
                p95=values[math.ceil(.95 * len(values)) - 1] * 1000,
                maximum=values[-1] * 1000, sum=sum(values) * 1000)


distributions = {}
for thread_kind in ['main', 'workers']:
    chosen = [event for event in events if (event['thread'] == main) == (thread_kind == 'main')]
    for operation in ['write', 'writev', 'fsync', 'fdatasync', 'lseek', 'futex']:
        values = [event['elapsed_s'] for event in chosen if event['operation'] == operation
                  and (operation == 'futex' or (event['path'] and event['path'].endswith('.jnl')))]
        if values:
            distributions[thread_kind + ':' + operation] = percentiles(values)
roots = []
candidates = []
states = {}
for event in events:
    path = event['path']
    if event['thread'] != main or not path or not path.endswith('.jnl'):
        continue
    assert event['returned'] >= 0
    state = states.setdefault((path, event['descriptor']), dict(writes=[], sync=None))
    if event['operation'] in ['write', 'writev']:
        root = str(pathlib.Path(path).parent)
        if root not in roots:
            roots.append(root)
        assert roots[-1] == root
        state['writes'].append(event)
        state['sync'] = None
    elif event['operation'] in ['fsync', 'fdatasync']:
        if state['writes']:
            assert state['sync'] is None
            state['sync'] = event
    elif event['operation'] == 'lseek' and event['arguments'].endswith(', 0, SEEK_CUR'):
        if state['sync']:
            assert event['started_s'] >= state['sync']['started_s'] + state['sync']['elapsed_s'] - 0.000002
            candidates.append(dict(path=path, offset=event['returned'], sync=state['sync'],
                                   writes=state['writes'], position=event))
            state.update(writes=[], sync=None)
assert len(roots) == len(report['runs']) == 8
matched = []
for index, run in enumerate(report['runs']):
    for sample in run['samples']:
        for phase, key in [('source', 'source_cursor'), ('output', 'graph_cursor')]:
            cursor = sample[key]
            path = str(pathlib.Path(roots[index]) / (str(cursor['journal']) + '.jnl'))
            matches = [candidate for candidate in candidates
                       if candidate['path'] == path and candidate['offset'] == cursor['offset']]
            assert len(matches) == 1, (index, phase, cursor, len(matches))
            candidate = matches[0]
            matched.append(dict(run=index, engine=run['engine'], round=run['round'],
                                revision=sample['revision'], restarted=sample['restarted'],
                                phase=phase, cursor=cursor, path=path,
                                fsync_ms=candidate['sync']['elapsed_s'] * 1000,
                                write_count=len(candidate['writes']),
                                write_bytes=sum(event['returned'] for event in candidate['writes']),
                                writes_ms=sum(event['elapsed_s'] for event in candidate['writes']) * 1000,
                                sync_start_s=candidate['sync']['started_s'],
                                position_start_s=candidate['position']['started_s']))
assert len(matched) == 128
ordinary = {}
for engine in ['fjall', 'fjall-stable']:
    for phase in ['source', 'output']:
        chosen = [item for item in matched if item['engine'] == engine
                  and item['phase'] == phase and not item['restarted']]
        assert len(chosen) == 28
        ordinary[engine + ':' + phase] = dict(
            fsync_ms=percentiles(item['fsync_ms'] / 1000 for item in chosen),
            writes_ms=percentiles(item['writes_ms'] / 1000 for item in chosen),
            write_counts=dict(collections.Counter(item['write_count'] for item in chosen)))
result = dict(
    scope='Diagnostic only. All traced timings excluded from acceptance. Full existing combined driver.',
    limits=['Syscall elapsed time includes tracing and scheduling; it is not pure device time.',
            'Futex durations do not identify a specific channel or lock.',
            'Worker elapsed sums overlap each other and main work; do not add them as wall time.',
            'Journal roots map to sequential report runs by first main-thread write; no root interleaving is allowed.',
            'Each saved cursor must match exactly one write-sync-position candidate on the same journal path.'],
    main_thread=main, completed_events=len(events), main_and_worker_distributions_ms=distributions,
    journal_roots=roots, candidates=len(candidates), matched_cursors=len(matched),
    ordinary_journal_distributions=ordinary, commits=matched)
(directory / 'wait-current-analysis.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({key: value for key, value in result.items() if key != 'commits'}, indent=2))
