import hashlib
import importlib.util
import json
import math
import pathlib
import shutil
import statistics
import subprocess
import tarfile

base = pathlib.Path('crates/araphor-graph/examples/storage_poc')
out = pathlib.Path('output/storage-engine-baseline-20261108')
cache = pathlib.Path('/tmp/araphor-callgrind')
destination = base / 'results/versioned-engine-2026-11-08/checked-handles'
destination.mkdir(exist_ok=False)
summaries = {}
for name in ['cdc', 'stable']:
    spec = importlib.util.spec_from_file_location(name, base / f'summarize_{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summaries['combined' if name == 'cdc' else 'stable'] = module.summarize

record = dict(performance='Not done', summary_checks=[], elapsed=[], binaries={})
for path in sorted(out.glob('*handle-*.json')):
    if path.name.endswith('-summary.json'):
        continue
    mode = next((mode for mode in summaries if f'-{mode}-' in path.name), None)
    if mode is None:
        continue
    report = json.loads(path.read_text())
    summary = summaries[mode](report)
    assert summary == json.loads(path.with_name(path.stem + '-summary.json').read_text())
    record['summary_checks'].append(path.name)
    shutil.copy2(path, destination / path.name)
    shutil.copy2(path.with_name(path.stem + '-summary.json'), destination / (path.stem + '-summary.json'))
    row = dict(report=path.name, mode=mode, source=report['source'])
    if mode == 'combined':
        selected = [sample for run in report['runs'] if run['engine'] == 'fjall-stable'
                    for sample in run['samples'] if not sample['restarted']]
        values = sorted(sample['total_s'] * 1000 for sample in selected)
        assert len(values) == 28
        row.update(samples=len(values), minimum_ms=values[0], median_ms=statistics.median(values),
                   p95_ms=values[math.ceil(.95 * len(values)) - 1], maximum_ms=values[-1])
        assert math.isclose(row['median_ms'], summary['engines']['fjall-stable']['ordinary_ms']['total']['median'], abs_tol=1e-12)
    else:
        row['eight_cycles_ms'] = summary['engines']['fjall-stable']['eight_cycles_ms']
    record['elapsed'].append(row)
assert len(record['summary_checks']) == 16

for prefix in ['handle', 'checked-handle']:
    for side in ['before', 'after']:
        path = cache / f'{prefix}-{side}-package-combined.json'
        summary = summaries['combined'](json.loads(path.read_text()))
        assert summary == json.loads(path.with_name(f'{prefix}-{side}-package-summary.json').read_text())
        record['summary_checks'].append(path.name)
    result = json.loads((cache / f'{prefix}-package-instructions.json').read_text())
    record[prefix + '_instructions'] = {
        key: value for key, value in result.items() if key != 'sides'}
    record[prefix + '_instructions']['sides'] = {
        side: {key: value for key, value in data.items()
               if key in ['source', 'ordinary_samples', 'ordinary_calls', 'ordinary_table_instructions',
                          'ordinary_instructions', 'ordinary_median_instructions',
                          'zero_residual_and_worker_profiles']}
        for side, data in result['sides'].items()}

for side in ['before', 'after']:
    path = cache / f'handle-{side}-table-combined.json'
    summary = summaries['combined'](json.loads(path.read_text()))
    saved = path.with_name(f'handle-{side}-table-summary.json')
    if saved.exists():
        assert summary == json.loads(saved.read_text())
    (destination / saved.name).write_text(json.dumps(summary, indent=2) + '\n')
    record['summary_checks'].append(path.name)
assert len(record['summary_checks']) == 22

for name in ['versioned-direct-decoder', 'versioned-borrowed-handles', 'versioned-checked-handles']:
    path = out / name
    record['binaries'][name] = dict(bytes=path.stat().st_size,
                                  sha256=hashlib.sha256(path.read_bytes()).hexdigest())
assert record['binaries']['versioned-checked-handles']['sha256'] == 'c1e3e602b7758b5945fbd4ac4f6b58c6c7616dd369e78792874a5f2bd34a45e3'
assert record['binaries']['versioned-direct-decoder']['sha256'] == 'd4f84259d53519011f19775802991b72f750723614be9ef4a795e86a9963d31a'
record['source'] = {name: subprocess.check_output(['git', '-C', name, 'rev-parse', 'HEAD'], text=True).strip()
                    for name in ['fjall', 'lsm-tree']}
assert not subprocess.check_output(['git', '-C', 'lsm-tree', 'diff', 'HEAD'], text=True)
for prefix in ['handle', 'checked-handle']:
    for suffix in ['gates.json', 'binary.json', 'patch']:
        path = out / f'{prefix}-{suffix}' if suffix != 'patch' else out / f'{prefix}.patch'
        if path.exists():
            shutil.copy2(path, destination / path.name)
for source, target in [
    ('/tmp/araphor-checked-handle-comparison.py', 'compare.py'),
    ('/tmp/araphor-handle-comparison.py', 'compare-draft.py'),
    ('/tmp/araphor-checked-handle-gates.py', 'gates.py'),
    ('/tmp/araphor-handle-gates.py', 'gates-draft.py'),
    ('/tmp/araphor-checked-handle-build.py', 'build.py'),
    ('/tmp/araphor-handle-build.py', 'build-draft.py'),
    ('/tmp/araphor-checked-handle-package-profiles.py', 'profile-package.py'),
    ('/tmp/araphor-handle-package-profiles.py', 'profile-draft-package.py'),
    ('/tmp/araphor-handle-profiles.py', 'profile-excluded.py'),
    (cache / 'analyze-checked-handle.py', 'analyze-package.py'),
    (cache / 'analyze-handle.py', 'analyze-draft-package.py'),
    (cache / 'analyze-handle-excluded.py', 'analyze-excluded.py'),
    ('/tmp/araphor-publish-checked-handles.py', 'publish.py'),
]:
    shutil.copy2(source, destination / target)
for name in ['tool.json', 'release-override.toml']:
    shutil.copy2(destination.parent / 'point-decoder' / name, destination / name)
environment = json.loads((destination.parent / 'point-decoder/environment.json').read_text())
environment['observation_limit'] = 'Inherited earlier host and tool observation from point-decoder at the recorded timestamp. It does not establish host load or build environment during the checked-handles measurements.'
(destination / 'environment.json').write_text(json.dumps(environment, indent=2) + '\n')

files = {}
for directory, label in [(cache, 'callgrind'), (out, 'reports')]:
    for pattern in ['handle-*', 'checked-handle-*', 'handle.patch', 'checked-handle.patch']:
        for path in directory.glob(pattern):
            if path.is_file():
                files[label + '/' + path.name] = path
archive = destination / 'raw-evidence.tar.zst'
command = ['zstd', '-q', '-T2', '-3', '--long=27', '-o', str(archive)]
process = subprocess.Popen(command, stdin=subprocess.PIPE)
with tarfile.open(fileobj=process.stdin, mode='w|') as handle:
    for name, path in sorted(files.items()):
        handle.add(path, arcname=name)
process.stdin.close()
assert process.wait() == 0
print('Archive written; checking every member byte against its source.', flush=True)
process = subprocess.Popen(['zstd', '-q', '-d', '-c', str(archive)], stdout=subprocess.PIPE)
with tarfile.open(fileobj=process.stdout, mode='r|') as handle:
    names = set()
    for member in handle:
        assert member.name not in names
        names.add(member.name)
        source = files[member.name]
        assert member.size == source.stat().st_size
        with source.open('rb') as expected:
            actual = handle.extractfile(member)
            while chunk := expected.read(1 << 20):
                assert actual.read(len(chunk)) == chunk, member.name
            assert not actual.read(1)
    assert names == set(files)
process.stdout.close()
assert process.wait() == 0
record.update(archive_members=len(files), archive_bytes=archive.stat().st_size,
              uncompressed_bytes=sum(path.stat().st_size for path in files.values()),
              archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
              archive_members_verified=True, compression_command=command,
              p95_method='Nearest rank; 28 ordinary fixed-key samples; restart excluded.',
              excluded='The initial method-only collector has a six-instruction conservation mismatch in before part 11. Both method-only profiles are excluded.',
              limits='Profiled timings are excluded. Native costs are nested actual entered calls. Initial unchecked draft is superseded. No repeatable elapsed gain is proved.')
(destination / 'verification.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(destination=str(destination), members=len(files), bytes=archive.stat().st_size), indent=2))
