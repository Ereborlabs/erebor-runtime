import importlib.util
import json
import pathlib
import subprocess

base = pathlib.Path('crates/araphor-graph/examples/storage_poc')
out = pathlib.Path('output/storage-engine-baseline-20261108')
summaries = {}
for mode, name in [('combined', 'summarize_cdc'), ('stable', 'summarize_stable')]:
    spec = importlib.util.spec_from_file_location(name, base / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summaries[mode] = module.summarize
order = [
    ('before', 'combined', 0), ('after', 'combined', 0),
    ('after', 'stable', 0), ('before', 'stable', 0),
    ('after', 'combined', 1), ('before', 'combined', 1),
    ('before', 'stable', 1), ('after', 'stable', 1),
]
for side, mode, number in order:
    binary = out / ('control' if side == 'before' else 'versioned-direct-compression')
    stem = f'current-{side}-{mode}-{number}'
    path = out / (stem + '.json')
    with (out / (stem + '.log')).open('w') as log:
        subprocess.run([str(binary), str(path), mode], stdout=log, stderr=subprocess.STDOUT, check=True)
    result = summaries[mode](json.loads(path.read_text()))
    (out / (stem + '-summary.json')).write_text(json.dumps(result, indent=2) + '\n')
    measured = result['engines']['fjall-stable']
    if mode == 'combined':
        print(stem, measured['ordinary_ms']['total'], flush=True)
    else:
        print(stem, measured['eight_cycles_ms'], flush=True)
