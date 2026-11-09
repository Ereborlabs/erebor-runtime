import collections
import importlib.util
import json
import pathlib
import re

directory = pathlib.Path('/tmp/araphor-callgrind')
target = 'storage_poc::package::evaluate'
spec = importlib.util.spec_from_file_location(
    'summarize_cdc', 'crates/araphor-graph/examples/storage_poc/summarize_cdc.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def parse(path):
    names = {}
    events = []
    models = []
    exclusive = {}
    inclusive = {}
    calls = collections.Counter()
    own = called = ''
    pending = False
    total = header = None
    part = thread = None
    trigger = ''
    padded = 0
    for line in path.open():
        line = line.rstrip('\n')
        if line.startswith('events:'):
            events = line.split()[1:]
        elif line.startswith('positions:'):
            assert line == 'positions: line'
        elif line.startswith('desc:') and 'cache:' in line:
            models.append(line)
        elif line.startswith('desc: Trigger:'):
            trigger = line
        elif line.startswith('part:'):
            part = int(line.split()[1])
        elif line.startswith('thread:'):
            thread = int(line.split()[1])
        elif line.startswith(('summary:', 'totals:')):
            values = [int(item) for item in line.split()[1:]]
            assert len(values) <= len(events)
            values += [0] * (len(events) - len(values))
            if line.startswith('summary:'):
                header = values
            else:
                total = values
        elif match := re.match(r'^(c?)fn=\((\d+)\)(?: (.*))?$', line):
            kind, identity, name = match.groups()
            if name is not None:
                names[identity] = name
            name = names[identity].split("'", 1)[0]
            if kind:
                called = name
            else:
                own = name
                pending = False
        elif line.startswith('calls='):
            calls[called] += int(line.split()[0].split('=')[1])
            pending = True
        elif re.match(r'^(?:\d+|\*|[+-]\d+)\s+', line):
            values = [int(item) for item in line.split()[1:]]
            assert len(values) <= len(events)
            padded += len(values) < len(events)
            values += [0] * (len(events) - len(values))
            costs = inclusive if pending else exclusive
            name = called if pending else own
            counters = costs.setdefault(name, [0] * len(events))
            for index, value in enumerate(values):
                counters[index] += value
            pending = False
    summed = [sum(values[index] for values in exclusive.values()) for index in range(len(events))]
    assert header == total == summed == inclusive.get(target, [0] * len(events)), path.name
    return dict(events=events, models=models, total=total, calls=calls, part=part, thread=thread,
                trigger=trigger, exclusive=exclusive, inclusive=inclusive, padded_lines=padded)


def untimed(value):
    if isinstance(value, dict):
        return {key: untimed(item) for key, item in value.items()
                if not key.endswith('_s') and key not in ['source_cursor', 'graph_cursor']}
    if isinstance(value, list):
        return [untimed(item) for item in value]
    return value


results = {}
layout = models = None
for side in ['cache-control', 'cache-current']:
    report = json.loads((directory / (side + '-package-combined.json')).read_text())
    summary = module.summarize(report)
    (directory / (side + '-package-summary.json')).write_text(json.dumps(summary, indent=2) + '\n')
    paths = sorted(directory.glob(side + '-package.out.*-01'),
                   key=lambda path: int(path.name.split('.out.')[1].split('-')[0]))
    assert len(paths) == 72, (side, len(paths))
    samples = []
    exclusive = {}
    inclusive = {}
    residual = []
    padded = 0
    for number, path in enumerate(paths):
        parsed = parse(path)
        if layout is None:
            layout, models = parsed['events'], parsed['models']
            assert len(layout) == 14 and 'Ge' in layout
        assert parsed['events'] == layout and parsed['models'] == models
        assert parsed['part'] == number + 1 and parsed['thread'] == 1
        assert parsed['trigger'] == 'desc: Trigger: --dump-after=' + target
        assert parsed['calls'][target] == 1
        padded += parsed['padded_lines']
        run_number, step = divmod(number, 9)
        run = report['runs'][run_number]
        sample = run['samples'][step] if step < 8 else None
        ordinary = run['engine'] == 'fjall-stable' and step < 8 and step != 4
        if sample:
            assert sample['restarted'] == (step == 4)
        if ordinary:
            for name, costs in [('exclusive', exclusive), ('inclusive', inclusive)]:
                for method, values in parsed[name].items():
                    counters = costs.setdefault(method, [0] * len(layout))
                    for index, value in enumerate(values):
                        counters[index] += value
        samples.append(dict(profile=path.name, run=run_number, engine=run['engine'],
                            round=run['round'], step=step, ordinary=ordinary,
                            revision=sample['revision'] if sample else 88,
                            events=dict(zip(layout, parsed['total'], strict=True)),
                            reported_work=untimed(sample) if ordinary else None))
    for path in directory.glob(side + '-package.out*'):
        if path in paths or path.stat().st_size == 0:
            continue
        parsed = parse(path)
        assert parsed['events'] == layout and parsed['models'] == models
        assert not any(parsed['total']) and parsed['calls'][target] == 0, path.name
        residual.append(path.name)
    ordinary = [sample for sample in samples if sample['ordinary']]
    assert len(ordinary) == 28
    totals = {event: sum(sample['events'][event] for sample in ordinary) for event in layout}
    assert [totals[event] for event in layout] == inclusive[target]
    assert [totals[event] for event in layout] == [
        sum(values[index] for values in exclusive.values()) for index in range(len(layout))]
    results[side] = dict(source=report['source'], ordinary_samples=28, samples=samples,
                         totals=totals, padded_cost_lines=padded,
                         zero_residual_and_worker_profiles=residual,
                         exclusive={name: dict(zip(layout, values, strict=True)) for name, values in exclusive.items()},
                         inclusive={name: dict(zip(layout, values, strict=True)) for name, values in inclusive.items()})
    print(side, totals, flush=True)
    for event in ['Ge', 'I1mr', 'D1mr', 'Bim']:
        print(event, sorted(((name, values[layout.index(event)]) for name, values in exclusive.items()),
                            key=lambda pair: pair[1], reverse=True)[:10], flush=True)
before, after = results.values()
assert [sample['reported_work'] for sample in before['samples']] == [sample['reported_work'] for sample in after['samples']]
record = dict(
    scope='28 complete ordinary fixed-key package evaluations; 72 actual entries per driver.',
    events=layout, cache_model=models, collection='Continuous instrumentation; entry clears counters only.',
    limits='Ge counts operations, not contention/cycles. Cache/predictor misses are simulated, not hardware measurements. Profile timings excluded.',
    change_percent={event: 100 * (after['totals'][event] / before['totals'][event] - 1)
                    if before['totals'][event] else None for event in layout},
    sides=results)
(directory / 'cache-package-events.json').write_text(json.dumps(record, indent=2) + '\n')
print('change percent', record['change_percent'], flush=True)
