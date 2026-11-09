import hashlib
import importlib.util
import json
import math
import pathlib
import statistics
import subprocess

base = pathlib.Path('crates/araphor-graph/examples/storage_poc')
out = pathlib.Path('output/storage-engine-baseline-20261108')
profiles = pathlib.Path('/tmp/araphor-callgrind')
summaries = {}
for mode, name in [('combined', 'summarize_cdc'), ('stable', 'summarize_stable')]:
    spec = importlib.util.spec_from_file_location(name, base / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summaries[mode] = module.summarize


def untimed(value):
    if isinstance(value, dict):
        return {key: untimed(item) for key, item in value.items()
                if key != 'source' and not key.endswith('_s')}
    if isinstance(value, list):
        return [untimed(item) for item in value]
    return value


record = dict(summary_checks=[], ordinary_percentiles_ms=[], stable_eight_cycle_ms={},
              p95_method='Nearest rank; sample 27 of 28; restart separate.',
              full_workspace_ci='Not run during iteration, as the user requires.')
for mode in ['combined', 'stable']:
    for number in [0, 1]:
        reports = []
        for side in ['before', 'after']:
            path = out / f'decoder-{side}-{mode}-{number}.json'
            report = json.loads(path.read_text())
            summary = summaries[mode](report)
            assert summary == json.loads(path.with_name(path.stem + '-summary.json').read_text())
            record['summary_checks'].append(path.name)
            reports.append(report)
            if mode == 'combined':
                values = sorted(sample['total_s'] * 1000 for run in report['runs']
                                if run['engine'] == 'fjall-stable'
                                for sample in run['samples'] if not sample['restarted'])
                assert len(values) == 28
                record['ordinary_percentiles_ms'].append(dict(
                    report=path.name, samples=len(values), minimum=min(values),
                    median=statistics.median(values), p95=values[math.ceil(.95 * len(values)) - 1],
                    maximum=max(values)))
            else:
                record['stable_eight_cycle_ms'][path.name] = summary['engines']['fjall-stable']['eight_cycles_ms']
        assert untimed(reports[0]) == untimed(reports[1])
record['non_timing_reports_match'] = True
for side in ['point-native-before', 'point-native-after']:
    report = json.loads((profiles / (side + '-combined.json')).read_text())
    assert summaries['combined'](report) == json.loads((profiles / (side + '-summary.json')).read_text())
    record['summary_checks'].append(side + '-combined.json')
before, after = json.loads((profiles / 'point-instructions.json').read_text())['sides'].values()
assert before['calls'] == after['calls'] == 105692 and before['work'] == after['work']
assert all(p['instructions'] == 0 for side in [before, after]
           for p in side['profiles'] if not p['profile'].endswith('-01'))
record['native_point_diagnostic'] = dict(
    scope='All actual data-block point reads across both layouts and all stages; profiled timings excluded.',
    calls=before['calls'], before_instructions=before['instructions'], after_instructions=after['instructions'],
    instruction_change_percent=100 * (after['instructions'] / before['instructions'] - 1),
    equal_reported_domain_work=True, raw_headers_exclusive_and_target_inclusive_equal=True,
    worker_instructions=0)
manifest = json.loads((out / 'decoder-binary.json').read_text())
patch = (out / 'decoder.patch').read_bytes()
assert hashlib.sha256(patch).hexdigest() == manifest['patch_sha256']
assert patch == subprocess.check_output(['git', '-C', 'lsm-tree', 'diff', '--binary', manifest['lsm_tree_base']])
for key, digest in [('binary', 'binary_sha256'), ('before_binary', 'before_binary_sha256')]:
    assert hashlib.sha256(pathlib.Path(manifest[key]).read_bytes()).hexdigest() == manifest[digest]
assert all(gate['exit_code'] == 0 for gate in json.loads((out / 'decoder-gates.json').read_text()))
assert json.loads((out / 'decoder-build.json').read_text())['exit_code'] == 0
record['all_patch_and_binary_hashes_verified'] = True
(out / 'decoder-verification.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, indent=2))
