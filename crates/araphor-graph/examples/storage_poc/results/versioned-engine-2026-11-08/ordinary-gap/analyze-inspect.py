import collections
import importlib.util
import json
import pathlib
import re
import statistics

directory = pathlib.Path('/tmp/araphor-callgrind')
target = '<storage_poc::native::Native>::inspect'
spec = importlib.util.spec_from_file_location(
    'summarize_cdc', 'crates/araphor-graph/examples/storage_poc/summarize_cdc.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def parse(path):
    lines = path.read_text().splitlines()
    assert 'positions: line' in lines and 'events: Ir' in lines
    names = {m[1]: m[2] for line in lines
             if (m := re.match(r'c?fn=\((\d+)\) (.+)', line))}
    exclusive = collections.Counter()
    inclusive = collections.Counter()
    calls = collections.Counter()
    own = called = ''
    pending = False
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
                exclusive[own] += int(m[1])
    total = int(next(line.split()[1] for line in lines if line.startswith('totals:')))
    header = int(next(line.split()[1] for line in lines if line.startswith('summary:')))
    assert total == header == sum(exclusive.values()) == inclusive[target], path.name
    return total, exclusive, inclusive, calls, lines


def untimed(value):
    if isinstance(value, dict):
        return {key: untimed(item) for key, item in value.items()
                if not key.endswith('_s') and key not in ['source_cursor', 'graph_cursor']}
    if isinstance(value, list):
        return [untimed(item) for item in value]
    return value


results = {}
for side in ['result-control', 'result-current']:
    report = json.loads((directory / (side + '-inspect-combined.json')).read_text())
    summary = module.summarize(report)
    (directory / (side + '-inspect-summary.json')).write_text(json.dumps(summary, indent=2) + '\n')
    paths = sorted(directory.glob(side + '-inspect.out.*-01'),
                   key=lambda path: int(path.name.split('.out.')[1].split('-')[0]))
    assert len(paths) == 200, (side, len(paths))
    samples = []
    exclusive = collections.Counter()
    inclusive = collections.Counter()
    workers = []
    for number, path in enumerate(paths):
        total, own, nested, calls, lines = parse(path)
        assert f'part: {number + 1}' in lines and 'thread: 1' in lines
        assert 'desc: Trigger: --dump-after=' + target in lines
        assert calls[target] == 1
        run_number, step = divmod(number, 25)
        run = report['runs'][run_number]
        sample = run['samples'][step] if step < 8 else None
        ordinary = run['engine'] == 'fjall-stable' and step < 8 and step != 4
        if sample:
            assert sample['restarted'] == (step == 4)
        if ordinary:
            exclusive.update(own)
            inclusive.update(nested)
        samples.append(dict(profile=path.name, run=run_number, engine=run['engine'],
                            round=run['round'], step=step, ordinary=ordinary,
                            revision=sample['revision'] if sample else None,
                            calls=calls[target], instructions=total,
                            reported_work=untimed(sample) if ordinary else None))
    for path in directory.glob(side + '-inspect.out*'):
        if path in paths or path.stat().st_size == 0:
            continue
        total, _, _, calls, _ = parse(path)
        assert total == 0 and calls[target] == 0, path.name
        workers.append(path.name)
    ordinary = [sample for sample in samples if sample['ordinary']]
    assert len(ordinary) == 28
    results[side] = dict(
        source=report['source'], samples=samples, ordinary_samples=len(ordinary),
        ordinary_instructions=sum(s['instructions'] for s in ordinary),
        ordinary_median_instructions=statistics.median(s['instructions'] for s in ordinary),
        revision_medians={str(revision): statistics.median(
            s['instructions'] for s in ordinary if s['revision'] == revision)
            for revision in sorted({s['revision'] for s in ordinary})},
        exclusive=dict(exclusive.most_common()), inclusive=dict(inclusive.most_common()),
        zero_residual_and_worker_profiles=workers,
        history=[dict(engine=run['engine'], round=run['round'],
                      historical_views=run['historical_views'], unavailable=run['unavailable'])
                 for run in report['runs']])
    assert results[side]['ordinary_instructions'] == sum(exclusive.values()) == inclusive[target]
    print(side, results[side]['ordinary_instructions'], results[side]['ordinary_median_instructions'])
    print('revisions', results[side]['revision_medians'])
    print('exclusive', exclusive.most_common(12))
    print('inclusive', inclusive.most_common(16))
before, after = results.values()
assert [s['reported_work'] for s in before['samples']] == [s['reported_work'] for s in after['samples']]
record = dict(
    metric='Instructions inside 28 actual ordinary fixed-key result inspections.',
    excluded='Profile timings, restart, rollback and history inspections.',
    mapping='200 actual inspect dumps; 25 per run: 8 primary, 1 rollback, 16 history.',
    report_equality='Ordinary sample fields match except timings and physical native cursor positions. History differences retained.',
    instruction_change_percent=100 * (after['ordinary_instructions'] / before['ordinary_instructions'] - 1),
    sides=results)
(directory / 'ordinary-inspect-instructions.json').write_text(json.dumps(record, indent=2) + '\n')
print('change percent', record['instruction_change_percent'])
