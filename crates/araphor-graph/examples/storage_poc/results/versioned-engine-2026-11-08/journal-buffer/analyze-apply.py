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
target = '<storage_poc::native::Native>::apply_saved'
results = {}
for side in ['apply-control', 'apply-current', 'apply-cursor', 'apply-reused']:
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
        total = int(next(line.split()[1] for line in lines if line.startswith('totals:')))
        header = int(next(line.split()[1] for line in lines if line.startswith('summary:')))
        assert sum(costs.values()) == total == header, path.name
        if not path.name.endswith('-01'):
            assert total == 0
        exclusive.update(costs)
        profiles.append(dict(profile=path.name, instructions=total))
    assert profiles and calls[target] == 72
    assert inclusive[target] == sum(exclusive.values())
    path = directory / (side + '-combined.json')
    report = json.loads(path.read_text())
    summary = module.summarize(report)
    path.with_name(side + '-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    work = [[{key: sample[key] for key in ['revision', 'captured', 'added', 'closed', 'findings',
                                           'members', 'result_rows', 'output_bytes']}
             for sample in run['samples']] for run in report['runs']]
    results[side] = dict(instructions=sum(exclusive.values()), calls=calls[target],
                         profiles=profiles, work=work, exclusive=dict(exclusive.most_common()),
                         inclusive=dict(inclusive.most_common()), calls_by_function=dict(calls))
    print(side, results[side]['instructions'], 'calls', calls[target])
    print('exclusive', exclusive.most_common(16))
    print('inclusive', inclusive.most_common(16))
    print('history', {key: value for key, value in inclusive.items()
                      if 'versioned::history' in key or 'Retention' in key})
assert results['apply-control']['work'] == results['apply-current']['work']
assert results['apply-current']['work'] == results['apply-cursor']['work']
assert results['apply-current']['work'] == results['apply-reused']['work']
(directory / 'apply-instructions.json').write_text(json.dumps(dict(
    metric='Instructions inside 72 native apply calls; both layouts, including rollback; profiled timings excluded.',
    sides=results), indent=2) + '\n')
