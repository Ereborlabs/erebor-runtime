import importlib.util
import json
import pathlib
import re
import statistics
import sys

directory = pathlib.Path('/tmp/araphor-callgrind')
base = pathlib.Path('crates/araphor-graph/examples/storage_poc')
spec = importlib.util.spec_from_file_location('summarize_cdc', base / 'summarize_cdc.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
result = {
    'metric': 'Callgrind Ir; executed instructions, not elapsed time',
    'collection': 'native View query only; presence toggle collected no instructions',
    'selection': 'fjall-stable; eight primary cycles per run; restart and rollback excluded',
    'timing_use': 'all profiled timing fields are excluded from acceptance',
    'sides': {},
}
for side in sys.argv[1:]:
    report = json.loads((directory / (side + '-cycles-combined.json')).read_text())
    summary = module.summarize(report)
    (directory / (side + '-cycles-summary.json')).write_text(json.dumps(summary, indent=2) + '\n')
    files = sorted(directory.glob(side + '-cycles.out.*-01'),
                   key=lambda path: int(re.search(r'\.out\.(\d+)-01', path.name)[1]))
    assert len(files) == 72, (side, len(files))
    samples = []
    for number, path in enumerate(files):
        run_number, step = divmod(number, 9)
        run = report['runs'][run_number]
        sample = run['samples'][min(step, 7)]
        lines = path.read_text().splitlines()
        assert 'events: Ir' in lines
        names = {}
        for line in lines:
            match = re.match(r'c?fn=\((\d+)\) (.+)', line)
            if match:
                names[match[1]] = match[2]
        target = ''
        calls = 0
        for line in lines:
            match = re.match(r'cfn=\((\d+)\)', line)
            if match:
                target = names[match[1]].split("'", 1)[0]
            if line.startswith('calls=') and target == '<storage_poc::native::View as storage_poc::GraphRead>::query':
                calls += int(line.split()[0].split('=')[1])
        expected = sum(call['operation'] == 'neighbors' for call in sample['calls'])
        assert calls == expected, (path.name, calls, expected)
        assert step != 0 or next(line for line in lines if line.startswith('totals:')) == 'totals: 0'
        instructions = int(next(line.split()[1] for line in lines if line.startswith('totals:')))
        samples.append({
            'profile': path.name, 'run': run_number, 'engine': run['engine'],
            'round': run['round'], 'revision': sample['revision'] if step < 8 else 88,
            'rollback': step == 8, 'restarted': step == 4,
            'query_calls': calls, 'instructions': instructions,
        })
    ordinary = [sample for sample in samples if sample['engine'] == 'fjall-stable'
                and not sample['rollback'] and not sample['restarted']]
    assert len(ordinary) == 28
    result['sides'][side] = {
        'source': report['source'], 'validated_evaluations': len(samples),
        'ordinary_samples': len(ordinary),
        'ordinary_query_calls': sum(sample['query_calls'] for sample in ordinary),
        'ordinary_instructions': sum(sample['instructions'] for sample in ordinary),
        'ordinary_median_instructions': statistics.median(sample['instructions'] for sample in ordinary),
        'revision_medians': {str(revision): statistics.median(sample['instructions'] for sample in ordinary
                            if sample['revision'] == revision)
                            for revision in sorted({sample['revision'] for sample in ordinary})},
        'samples': samples,
    }
path = directory / ('-'.join(sys.argv[1:]) + '-instructions.json')
path.write_text(json.dumps(result, indent=2) + '\n')
for side, values in result['sides'].items():
    print(side, values['ordinary_instructions'], values['ordinary_median_instructions'])
