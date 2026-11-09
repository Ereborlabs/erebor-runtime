import collections
import importlib.util
import json
import pathlib
import re

directory = pathlib.Path('/tmp/araphor-callgrind')
base = pathlib.Path('crates/araphor-graph/examples/storage_poc')
spec = importlib.util.spec_from_file_location('summarize_cdc', base / 'summarize_cdc.py')
summarize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summarize)
result = {
    'metric': 'Callgrind Ir inside native feed calls; all threads and both layouts.',
    'timing_use': 'All profiled timing fields excluded from acceptance.',
    'selection': 'Complete existing combined driver; no ordinary-cycle or per-layout CPU claim.',
    'sides': {},
}
for side, target in [('control-cdc', '<fjall::cdc::Feed>::read'),
                     ('inline-cdc', '<fjall::cdc::Feed>::next_batch'),
                     ('checksum-cdc', '<fjall::cdc::Feed>::next_batch'),
                     ('header-cdc', '<fjall::cdc::Feed>::next_batch')]:
    report = json.loads((directory / (side + '-combined.json')).read_text())
    summary = summarize.summarize(report)
    (directory / (side + '-summary.json')).write_text(json.dumps(summary, indent=2) + '\n')
    exclusive = collections.Counter()
    inclusive = collections.Counter()
    calls = collections.Counter()
    profiles = []
    for path in sorted(directory.glob(side + '-profile.out-*')):
        lines = path.read_text().splitlines()
        assert 'positions: line' in lines and 'events: Ir' in lines
        names = {m[1]: m[2] for line in lines
                 if (m := re.match(r'c?fn=\((\d+)\) (.+)', line))}
        own = called = ''
        pending = False
        costs = collections.Counter()
        for line in lines:
            if m := re.match(r'(c?)fn=\((\d+)\)', line):
                if m[1]:
                    called = names[m[2]].split("'", 1)[0]
                else:
                    own = names[m[2]].split("'", 1)[0]
                    pending = False
            elif line.startswith('calls='):
                calls[called] += int(line.split()[0].split('=')[1])
                pending = True
            elif m := re.match(r'^(?:\d+|\*|[+-]\d+)\s+(\d+)\s*$', line):
                if pending:
                    inclusive[called] += int(m[1])
                    pending = False
                else:
                    costs[own] += int(m[1])
        totals = int(next(line.split()[1] for line in lines if line.startswith('totals:')))
        header = int(next(line.split()[1] for line in lines if line.startswith('summary:')))
        assert sum(costs.values()) == totals == header, path.name
        if path.name.endswith('-01'):
            assert totals == 0
        exclusive.update(costs)
        profiles.append(dict(profile=path.name, instructions=totals))
    assert calls[target] > 0 and inclusive[target] == sum(exclusive.values()), side
    assert len(report['runs']) == 8 and sum(len(run['samples']) for run in report['runs']) == 64
    walks = [walk for run in report['runs'] for walk in run['walks']]
    result['sides'][side] = dict(
        source=report['source'], instructions=sum(exclusive.values()), feed_calls=calls[target],
        profiles=profiles, native_batches=sum(w['batches'] for w in walks),
        native_items=sum(w['items'] for w in walks), journal_bytes=sum(w['journal_bytes'] for w in walks),
        source_wakes=sum(w['source_wakes'] for w in walks), graph_wakes=sum(w['graph_wakes'] for w in walks),
        exclusive=dict(exclusive.most_common()), inclusive=dict(inclusive.most_common()), calls=dict(calls))
    assert result['sides'][side]['source_wakes'] == result['sides'][side]['graph_wakes'] == 64
    print(side, result['sides'][side]['instructions'], calls[target], flush=True)
(directory / 'cdc-instructions.json').write_text(json.dumps(result, indent=2) + '\n')
