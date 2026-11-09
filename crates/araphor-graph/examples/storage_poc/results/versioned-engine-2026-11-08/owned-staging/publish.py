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
destination = base / 'results/versioned-engine-2026-11-08/owned-staging'
destination.mkdir(exist_ok=False)
summaries = {}
for name in ['cdc', 'stable']:
    spec = importlib.util.spec_from_file_location(name, base / f'summarize_{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summaries['combined' if name == 'cdc' else 'stable'] = module.summarize
record = dict(performance='Not done', elapsed=[], summary_checks=[])
for side in ['before', 'after']:
    for number in range(2):
        row = dict(side=side, pass_number=number + 1)
        for mode in ['combined', 'stable']:
            path = out / f'consume-{side}-{mode}-{number}.json'
            report = json.loads(path.read_text())
            summary = summaries[mode](report)
            saved = path.with_name(path.stem + '-summary.json')
            assert summary == json.loads(saved.read_text())
            shutil.copy2(saved, destination / saved.name)
            record['summary_checks'].append(path.name)
            if mode == 'combined':
                values = sorted(sample['total_s'] * 1000 for run in report['runs']
                                if run['engine'] == 'fjall-stable'
                                for sample in run['samples'] if not sample['restarted'])
                assert len(values) == 28
                row.update(samples=28, minimum_ms=values[0], median_ms=statistics.median(values),
                           p95_ms=values[math.ceil(.95 * len(values)) - 1], maximum_ms=values[-1])
            else:
                row['stable_ms'] = summary['engines']['fjall-stable']['eight_cycles_ms']
        record['elapsed'].append(row)
    path = cache / f'consume-{side}-apply-combined.json'
    summary = summaries['combined'](json.loads(path.read_text()))
    saved = path.with_name(f'consume-{side}-apply-summary.json')
    assert summary == json.loads(saved.read_text())
    shutil.copy2(saved, destination / saved.name)
    record['summary_checks'].append(path.name)
assert len(record['summary_checks']) == 10
result = json.loads((cache / 'consume-apply-instructions.json').read_text())
record['instructions'] = {key: value for key, value in result.items() if key != 'sides'}
record['instructions']['sides'] = {
    side: {key: value for key, value in data.items()
           if key in ['source', 'ordinary_samples', 'ordinary_instructions',
                      'ordinary_median_instructions', 'revision_medians',
                      'zero_residual_and_worker_profiles']}
    for side, data in result['sides'].items()}
record['nested_into_batch'] = {
    side: dict(calls=data['calls']['<fjall::tx::write_set::WriteSet>::into_batch'],
               instructions=data['inclusive']['<fjall::tx::write_set::WriteSet>::into_batch'])
    for side, data in result['sides'].items()}
manifest = json.loads((out / 'consume-binary.json').read_text())
for path_key, hash_key in [('binary', 'binary_sha256'), ('before_binary', 'before_binary_sha256')]:
    assert hashlib.sha256(pathlib.Path(manifest[path_key]).read_bytes()).hexdigest() == manifest[hash_key]
record['source'] = {name: subprocess.check_output(['git', '-C', name, 'rev-parse', 'HEAD'], text=True).strip()
                    for name in ['fjall', 'lsm-tree']}
for tree in record['source']:
    assert not subprocess.check_output(['git', '-C', tree, 'diff', 'HEAD'], text=True)
assert subprocess.check_output(['git', '-C', 'fjall', 'show', '--format=', '--binary', 'HEAD']) == (out / 'consume.patch').read_bytes()
for name in ['consume-binary.json', 'consume-gates.json', 'consume.patch']:
    shutil.copy2(out / name, destination / name)
for source, target in [('/tmp/araphor-consume-comparison.py', 'compare.py'),
                       ('/tmp/araphor-consume-gates.py', 'gates.py'),
                       ('/tmp/araphor-consume-build.py', 'build.py'),
                       ('/tmp/araphor-consume-profiles.py', 'profile.py'),
                       (cache / 'analyze-consume.py', 'analyze.py'),
                       ('/tmp/araphor-publish-consume.py', 'publish.py')]:
    shutil.copy2(source, destination / target)
for name in ['tool.json', 'release-override.toml']:
    shutil.copy2(destination.parent / 'checked-handles' / name, destination / name)
environment = json.loads((destination.parent / 'checked-handles/environment.json').read_text())
environment['observation_limit'] = 'Inherited earlier host and tool observation at the recorded timestamp. It does not establish host load or build environment during the owned-staging measurements.'
(destination / 'environment.json').write_text(json.dumps(environment, indent=2) + '\n')
files = {}
for directory, label in [(cache, 'callgrind'), (out, 'reports')]:
    for pattern in ['consume-*', 'consume.patch']:
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
              limits='Profiled timings are excluded. Native costs are nested actual entered calls. No repeatable elapsed gain is proved.')
(destination / 'verification.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(destination=str(destination), members=len(files), bytes=archive.stat().st_size), indent=2))
