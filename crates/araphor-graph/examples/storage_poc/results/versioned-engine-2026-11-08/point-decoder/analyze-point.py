import collections
import importlib.util
import json
import pathlib
import re

directory = pathlib.Path('/tmp/araphor-callgrind')
spec = importlib.util.spec_from_file_location(
    'summarize_cdc', 'crates/araphor-graph/examples/storage_poc/summarize_cdc.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
target = '<lsm_tree::table::data_block::DataBlock>::point_read'
results = {}
for side in ['point-native-before', 'point-native-after']:
    paths = sorted(directory.glob(side + '-profile.out-*'))
    if not paths:
        continue
    exclusive = collections.Counter()
    inclusive = collections.Counter()
    calls = collections.Counter()
    edges = collections.Counter()
    profiles = []
    for path in paths:
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
                    edges[(own, called)] += int(m[1])
                    pending = False
                else:
                    costs[own] += int(m[1])
        total = int(next(line.split()[1] for line in lines if line.startswith('totals:')))
        header = int(next(line.split()[1] for line in lines if line.startswith('summary:')))
        assert sum(costs.values()) == total == header, path.name
        if not path.name.endswith('-01'):
            assert total == 0
        exclusive.update(costs)
        profiles.append(dict(profile=path.name, instructions=total))
    assert calls[target] > 0 and inclusive[target] == sum(exclusive.values())
    report = json.loads((directory / (side + '-combined.json')).read_text())
    summary = module.summarize(report)
    (directory / (side + '-summary.json')).write_text(json.dumps(summary, indent=2) + '\n')
    work = [[{key: sample[key] for key in ['revision', 'captured', 'added', 'closed',
                                           'findings', 'members', 'result_rows', 'output_bytes']}
             for sample in run['samples']] for run in report['runs']]
    results[side] = dict(instructions=sum(exclusive.values()), calls=calls[target],
                         profiles=profiles, work=work, exclusive=dict(exclusive.most_common()),
                         inclusive=dict(inclusive.most_common()), calls_by_function=dict(calls),
                         edges=[dict(caller=a, callee=b, instructions=cost)
                                for (a, b), cost in edges.most_common()])
    print(side, results[side]['instructions'], 'calls', calls[target])
    print('exclusive', exclusive.most_common(12))
    print('inclusive', inclusive.most_common(12))
    print('point edges', [(a, b, cost) for (a, b), cost in edges.most_common()
                          if a == target or b == target])
if len(results) == 2:
    before, after = results.values()
    assert before['calls'] == after['calls'] and before['work'] == after['work']
(directory / 'point-instructions.json').write_text(json.dumps(dict(
    metric='All actual native data-block point reads across both layouts and all stages; profiled timings excluded.',
    sides=results), indent=2) + '\n')
