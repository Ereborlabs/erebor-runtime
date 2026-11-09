import datetime
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
out = pathlib.Path('output/storage-engine-simplify-20261109')
dest = base / 'results/versioned-engine-2026-11-08/simplification'
dest.mkdir(exist_ok=False)
manifest = json.loads((out / 'binary.json').read_text())
for tree, commit in manifest['source'].items():
    assert subprocess.check_output(['git', '-C', tree, 'rev-parse', 'HEAD'], text=True).strip() == commit
    assert not subprocess.check_output(['git', '-C', tree, 'status', '--porcelain'], text=True)
for entry in [manifest, manifest['before']]:
    assert hashlib.sha256(pathlib.Path(entry['binary']).read_bytes()).hexdigest() == entry['binary_sha256']
gates = json.loads((out / 'final-gates.json').read_text())
assert len(gates) == 11 and all(row['exit_code'] == 0 for row in gates)
summaries = {}
for mode, name in [('combined', 'cdc'), ('stable', 'stable')]:
    spec = importlib.util.spec_from_file_location(name, base / ('summarize_' + name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summaries[mode] = module.summarize

def without_times(value):
    if isinstance(value, dict):
        return {key: without_times(item) for key, item in value.items() if not key.endswith('_s')}
    if isinstance(value, list):
        return [without_times(item) for item in value]
    return value

pooled = {}
checks = []
for mode in ['combined', 'stable']:
    values = {'before': [], 'after': []}
    for number in range(4):
        reports = []
        for side in ['before', 'after']:
            path = out / f'{side}-{mode}-{number}.json'
            report = json.loads(path.read_text())
            summary = summaries[mode](report)
            saved = path.with_name(path.stem + '-summary.json')
            assert summary == json.loads(saved.read_text())
            shutil.copy2(saved, dest / saved.name)
            checks.append(path.name)
            if mode == 'combined':
                values[side].extend(sample['total_s'] * 1000 for run in report['runs']
                                    if run['engine'] == 'fjall-stable' for sample in run['samples']
                                    if not sample['restarted'])
            else:
                values[side].extend(sum(sample['scenario_s'] for sample in run['samples']) * 1000
                                    for run in report['runs'] if run['engine'] == 'fjall-stable')
            report.pop('source')
            reports.append(without_times(report))
        assert reports[0] == reports[1], (mode, number)
    pooled[mode] = {}
    for side, samples in values.items():
        assert len(samples) == (112 if mode == 'combined' else 16)
        ordered = sorted(samples)
        pooled[mode][side] = dict(samples=len(samples), median_ms=statistics.median(samples),
                                  p95_ms=ordered[math.ceil(.95 * len(ordered)) - 1],
                                  maximum_ms=ordered[-1])
assert len(checks) == 16
commits = {}
for label in ['a', 'b', 'c', 'd']:
    source = json.loads((out / (label + '-source.json')).read_text())['fjall']
    patch = out / (label + '.patch')
    assert patch.read_bytes() == subprocess.check_output(['git', '-C', 'fjall', 'show', '--format=', '--binary', source])
    commits[label] = dict(commit=source, patch_sha256=hashlib.sha256(patch.read_bytes()).hexdigest())
    shutil.copy2(patch, dest / patch.name)
for name in ['before.json', 'binary.json', 'build.json', 'final-gates.json',
             'commands.json', 'commands-2.json', 'measurements.json', 'measurements-2.json',
             'work-check.json', 'work-check-2.json']:
    shutil.copy2(out / name, dest / name)
for source, name in [('/tmp/araphor-simplify-build.py', 'build.py'),
                     ('/tmp/araphor-simplify-compare.py', 'compare.py'),
                     ('/tmp/araphor-simplify-publish.py', 'publish.py'),
                     ('/tmp/araphor-storage-release-override.toml', 'release-override.toml'),
                     ('fjall/Cargo.lock', 'fjall.Cargo.lock'),
                     ('lsm-tree/Cargo.lock', 'lsm-tree.Cargo.lock'),
                     (base / 'neon-bench/Cargo.lock', 'poc.Cargo.lock')]:
    shutil.copy2(source, dest / name)
environment = dict(recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   kernel=subprocess.check_output(['uname', '-a'], text=True).strip(),
                   rustc=subprocess.check_output(['rustc', '-Vv'], text=True).strip(),
                   cargo=subprocess.check_output(['cargo', '-V'], text=True).strip(),
                   limits='This observation follows the timing calls; it does not establish host load during them.')
(dest / 'environment.json').write_text(json.dumps(environment, indent=2) + '\n')
files = {'reports/' + path.name: path for path in out.iterdir()
         if path.is_file() and path.name != 'versioned-simplified'}
archive = dest / 'raw-evidence.tar.zst'
process = subprocess.Popen(['zstd', '-q', '-T2', '-3', '-o', str(archive)], stdin=subprocess.PIPE)
with tarfile.open(fileobj=process.stdin, mode='w|') as handle:
    for name, path in sorted(files.items()):
        handle.add(path, arcname=name)
process.stdin.close()
assert process.wait() == 0
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
                assert actual.read(len(chunk)) == chunk
            assert not actual.read(1)
    assert names == set(files)
process.stdout.close()
assert process.wait() == 0
record = dict(result='Done for the four approved simplifications on the observed PoC workload',
              source=manifest['source'], commits=commits, summary_checks=checks,
              gates_passed=11, full_non_time_reports_equal=True, physical_cursors_equal=True,
              pooled=pooled, p95_method='Nearest rank; ordinary fixed-key combined samples; restart excluded.',
              performance='Pooled median/p95/maximum and stable median do not regress. Individual comparisons are mixed. No repeatable latency gain or universal no-regression guarantee is proved.',
              limits='Large branch depths and long retained backlogs are not performance-benchmarked. Existing correctness tests cover selective updates and retained-segment replay. Full workspace CI is not run, as requested.',
              archive_members=len(files), archive_bytes=archive.stat().st_size,
              archive_uncompressed_bytes=sum(path.stat().st_size for path in files.values()),
              archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
              archive_members_verified=True)
(dest / 'verification.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(directory=str(dest), members=len(files), bytes=archive.stat().st_size, pooled=pooled), indent=2))
