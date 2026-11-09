import collections
import importlib.util
import json
import pathlib
import re
import statistics

directory = pathlib.Path('/tmp/araphor-callgrind')
target = 'storage_poc::package::evaluate'
owner = '<lsm_tree::table::Table>::get'
spec = importlib.util.spec_from_file_location(
    'summarize_cdc', 'crates/araphor-graph/examples/storage_poc/summarize_cdc.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def parse(path):
    lines = path.read_text().splitlines()
    assert 'positions: line' in lines and 'events: Ir' in lines
    names = {m[1]: m[2] for line in lines if (m := re.match(r'c?fn=\((\d+)\) (.+)', line))}
    exclusive = collections.Counter()
    inclusive = collections.Counter()
    calls = collections.Counter()
    contexts = collections.Counter()
    own = called = ''
    pending = False
    for line in lines:
        if m := re.match(r'(c?)fn=\((\d+)\)', line):
            if m[1]:
                full_called = names[m[2]]
                called = names[m[2]].split("'", 1)[0]
            else:
                own = names[m[2]].split("'", 1)[0]
                pending = False
        elif line.startswith('calls='):
            count = int(line.split()[0].split('=')[1])
            calls[called] += count
            if called == owner:
                contexts[full_called] += count
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
    return total, exclusive, inclusive, calls, lines, contexts


def untimed(value):
    if isinstance(value, dict):
        return {key: untimed(item) for key, item in value.items()
                if not key.endswith('_s') and key not in ['source_cursor', 'graph_cursor']}
    if isinstance(value, list):
        return [untimed(item) for item in value]
    return value


results = {}
for side in ['before', 'after']:
    prefix = 'checked-handle-' + side + '-package'
    report = json.loads((directory / (prefix + '-combined.json')).read_text())
    summary = module.summarize(report)
    (directory / (prefix + '-summary.json')).write_text(json.dumps(summary, indent=2) + '\n')
    paths = sorted(directory.glob(prefix + '.out.*-01'),
                   key=lambda path: int(path.name.split('.out.')[1].split('-')[0]))
    assert len(paths) == 72
    samples = []
    exclusive = collections.Counter()
    inclusive = collections.Counter()
    workers = []
    for number, path in enumerate(paths):
        total, own, nested, calls, lines, contexts = parse(path)
        assert f'part: {number + 1}' in lines and 'thread: 1' in lines
        assert 'desc: Trigger: --dump-after=storage_poc::package::evaluate' in lines
        assert calls[target] == 1
        run_number, step = divmod(number, 9)
        run = report['runs'][run_number]
        sample = run['samples'][step] if step < 8 else None
        if sample:
            assert sample['restarted'] == (step == 4)
        ordinary = run['engine'] == 'fjall-stable' and step not in [4, 8]
        if ordinary:
            exclusive.update(own)
            inclusive.update(nested)
        samples.append(dict(profile=path.name, run=run_number, engine=run['engine'],
                            round=run['round'], step=step, ordinary=ordinary,
                            revision=sample['revision'] if sample else 88,
                            table_calls=calls[owner], table_instructions=nested[owner],
                            context_calls=dict(contexts), instructions=total,
                            reported_work=untimed(sample) if sample else None))
    for path in directory.glob(prefix + '.out*'):
        if path in paths or path.stat().st_size == 0:
            continue
        total, _, _, calls, _, _ = parse(path)
        assert total == 0 and calls[target] == 0 and calls[owner] == 0, path.name
        workers.append(path.name)
    ordinary = [sample for sample in samples if sample['ordinary']]
    assert len(ordinary) == 28 and sum(s['table_calls'] for s in ordinary) > 0
    results[side] = dict(source=report['source'], samples=samples, ordinary_samples=28,
        ordinary_calls=sum(s['table_calls'] for s in ordinary),
        ordinary_table_instructions=sum(s['table_instructions'] for s in ordinary),
        ordinary_instructions=sum(s['instructions'] for s in ordinary),
        ordinary_median_instructions=statistics.median(s['instructions'] for s in ordinary),
        revision_medians={str(revision): statistics.median(s['instructions'] for s in ordinary
                          if s['revision'] == revision) for revision in sorted({s['revision'] for s in ordinary})},
        exclusive=dict(exclusive.most_common()), inclusive=dict(inclusive.most_common()),
        zero_residual_and_worker_profiles=workers)
    assert results[side]['ordinary_instructions'] == sum(exclusive.values()) == inclusive[target]
    assert results[side]['ordinary_table_instructions'] == inclusive[owner]
    print(side, results[side]['ordinary_calls'], results[side]['ordinary_instructions'],
          results[side]['ordinary_table_instructions'], flush=True)
before, after = results.values()
assert [s['reported_work'] for s in before['samples']] == [s['reported_work'] for s in after['samples']]
assert [s['table_calls'] for s in before['samples']] == [s['table_calls'] for s in after['samples']]
assert [s['context_calls'] for s in before['samples']] == [s['context_calls'] for s in after['samples']]
record = dict(metric='Complete package instructions for 28 ordinary fixed-key evaluations, with nested actual Table::get costs.',
              limits='All profiled timings excluded. Method costs are nested, not additive. No ordinary latency gain is implied.',
              mapping='72 actual evaluation-return dumps per driver; actual table-call counts match at every dump; residual/worker collection is zero.',
              instruction_change_percent=100 * (after['ordinary_instructions'] / before['ordinary_instructions'] - 1),
              table_instruction_change_percent=100 * (after['ordinary_table_instructions'] / before['ordinary_table_instructions'] - 1),
              sides=results)
(directory / 'checked-handle-package-instructions.json').write_text(json.dumps(record, indent=2) + '\n')
print('change percent', record['instruction_change_percent'], flush=True)
