import hashlib
import importlib.util
import json
import math
import pathlib
import statistics
import subprocess
import sys
import time

base = pathlib.Path('crates/araphor-graph/examples/storage_poc')
out = pathlib.Path('output/storage-engine-simplify-20261109')
manifest = json.loads((out / 'binary.json').read_text())
binaries = {'before': manifest['before']['binary'], 'after': manifest['binary']}
hashes = {'before': manifest['before']['binary_sha256'], 'after': manifest['binary_sha256']}
for side in binaries:
    assert hashlib.sha256(pathlib.Path(binaries[side]).read_bytes()).hexdigest() == hashes[side]
summaries = {}
for mode, name in [('combined', 'cdc'), ('stable', 'stable')]:
    spec = importlib.util.spec_from_file_location(name, base / ('summarize_' + name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summaries[mode] = module.summarize
order = [('before', 'combined', 0), ('after', 'combined', 0),
         ('after', 'stable', 0), ('before', 'stable', 0),
         ('after', 'combined', 1), ('before', 'combined', 1),
         ('before', 'stable', 1), ('after', 'stable', 1)]
commands = []
metrics = []
offset = int(sys.argv[1]) if len(sys.argv) > 1 else 0
suffix = '' if offset == 0 else '-' + str(offset)
for side, mode, number in order:
    number += offset
    path = out / f'{side}-{mode}-{number}.json'
    assert not path.exists()
    command = [binaries[side], str(path), mode]
    started = time.time()
    with path.with_suffix('.log').open('x') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    commands.append(dict(command=command, side=side, mode=mode, pass_number=number + 1,
                         exit_code=result.returncode, started=started, finished=time.time()))
    (out / ('commands' + suffix + '.json')).write_text(json.dumps(commands, indent=2) + '\n')
    assert result.returncode == 0
    report = json.loads(path.read_text())
    summary = summaries[mode](report)
    path.with_name(path.stem + '-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    selected = summary['engines']['fjall-stable']
    row = dict(side=side, mode=mode, pass_number=number + 1)
    if mode == 'combined':
        values = sorted(sample['total_s'] * 1000 for run in report['runs']
                        if run['engine'] == 'fjall-stable' for sample in run['samples']
                        if not sample['restarted'])
        assert len(values) == 28
        row.update(samples=len(values), median_ms=statistics.median(values),
                   p95_ms=values[math.ceil(.95 * len(values)) - 1], maximum_ms=values[-1])
    else:
        row.update(selected)
    metrics.append(row)
    (out / ('measurements' + suffix + '.json')).write_text(json.dumps(metrics, indent=2) + '\n')
    print(json.dumps(row), flush=True)

def without_times(value):
    if isinstance(value, dict):
        return {key: without_times(item) for key, item in value.items() if not key.endswith('_s')}
    if isinstance(value, list):
        return [without_times(item) for item in value]
    return value

for mode in ['combined', 'stable']:
    for number in range(offset, offset + 2):
        reports = [json.loads((out / f'{side}-{mode}-{number}.json').read_text())
                   for side in ['before', 'after']]
        for report in reports:
            report.pop('source')
        assert without_times(reports[0]) == without_times(reports[1]), (mode, number)
(out / ('work-check' + suffix + '.json')).write_text(json.dumps(dict(
    summaries_passed=8, full_non_time_reports_equal=True, physical_cursors_equal=True,
    excluded_fields='Only the top-level source label and timing fields ending in _s.'), indent=2) + '\n')
