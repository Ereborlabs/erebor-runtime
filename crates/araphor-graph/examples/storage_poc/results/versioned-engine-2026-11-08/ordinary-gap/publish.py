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
profiles = pathlib.Path('/tmp/araphor-callgrind')
destination = base / 'results/versioned-engine-2026-11-08/ordinary-gap'
destination.mkdir(exist_ok=False)
summaries = {}
for mode, name in [('combined', 'summarize_cdc'), ('stable', 'summarize_stable')]:
    spec = importlib.util.spec_from_file_location(name, base / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summaries[mode] = module.summarize


def untimed(value):
    if isinstance(value, dict):
        return {key: untimed(item) for key, item in value.items()
                if not key.endswith('_s') and key not in ['source_cursor', 'graph_cursor']}
    if isinstance(value, list):
        return [untimed(item) for item in value]
    return value


record = dict(performance='Not done', source_changes=False, summary_checks=[],
              ordinary_ms=[], stable_eight_cycle_ms={}, timing_breakdown={}, history=[],
              p95_method='Nearest rank; sample 27 of 28; restart separate.',
              timing_use='Only untraced driver timings support performance observations.')
for mode in ['combined', 'stable']:
    for number in [0, 1]:
        paired = {}
        for side in ['before', 'after']:
            path = out / f'original-gap-{side}-{mode}-{number}.json'
            report = json.loads(path.read_text())
            summary = summaries[mode](report)
            assert summary == json.loads(path.with_name(path.stem + '-summary.json').read_text())
            record['summary_checks'].append(path.name)
            if mode == 'combined':
                samples = [sample for run in report['runs'] if run['engine'] == 'fjall-stable'
                           for sample in run['samples'] if not sample['restarted']]
                assert len(samples) == 28
                paired[side] = samples
                values = sorted(sample['total_s'] * 1000 for sample in samples)
                record['ordinary_ms'].append(dict(report=path.name, samples=len(values),
                    minimum=min(values), median=statistics.median(values),
                    p95=values[math.ceil(.95 * len(values)) - 1], maximum=max(values)))
                record['history'].append(dict(report=path.name,
                    runs=[{key: run[key] for key in ['engine', 'round', 'historical_views', 'unavailable']}
                          for run in report['runs']]))
            else:
                record['stable_eight_cycle_ms'][path.name] = summary['engines']['fjall-stable']['eight_cycles_ms']
        if mode == 'combined':
            assert untimed(paired['before']) == untimed(paired['after'])
            fields = [key for key in paired['before'][0] if key.endswith('_s')]
            record['timing_breakdown'][str(number)] = {
                field: dict(
                    before_median=statistics.median(s[field] * 1000 for s in paired['before']),
                    after_median=statistics.median(s[field] * 1000 for s in paired['after']),
                    paired_delta_median=statistics.median(
                        (after[field] - before[field]) * 1000
                        for before, after in zip(paired['before'], paired['after'], strict=True)))
                for field in fields}
record['ordinary_work_matches'] = True
record['cpu_diagnostics'] = {}
for owner, file, prefixes in [
    ('query', 'ordinary-query-instructions.json', ['ordinary-control-cycles-', 'ordinary-current-cycles-']),
    ('inspect', 'ordinary-inspect-instructions.json', ['result-control-inspect-', 'result-current-inspect-']),
    ('package', 'ordinary-package-instructions.json', ['package-control-evaluate-', 'package-current-evaluate-']),
]:
    analysis = json.loads((profiles / file).read_text())
    before, after = analysis['sides'].values()
    record['cpu_diagnostics'][owner] = dict(before=before['ordinary_instructions'],
        after=after['ordinary_instructions'], change_percent=analysis['instruction_change_percent'],
        ordinary_samples=before['ordinary_samples'])
    shutil.copy2(profiles / file, destination / file)
    for prefix in prefixes:
        report = json.loads((profiles / (prefix + 'combined.json')).read_text())
        assert summaries['combined'](report) == json.loads((profiles / (prefix + 'summary.json')).read_text())
        record['summary_checks'].append(prefix + 'combined.json')
for source, target in [
    ('/tmp/araphor-ordinary-queries.py', 'profile-query.py'),
    ('/tmp/araphor-inspect-profiles.py', 'profile-inspect.py'),
    ('/tmp/araphor-evaluate-profiles.py', 'profile-package.py'),
    ('/tmp/araphor-original-comparison.py', 'compare.py'),
    ('/tmp/araphor-callgrind/analyze-ordinary.py', 'analyze-query.py'),
    ('/tmp/araphor-callgrind/analyze-inspect.py', 'analyze-inspect.py'),
    ('/tmp/araphor-callgrind/analyze-package.py', 'analyze-package.py'),
]:
    shutil.copy2(source, destination / target)
for source in ['ordinary-query-commands.json', 'result-inspect-commands.json', 'package-evaluate-commands.json']:
    shutil.copy2(profiles / source, destination / source)
shutil.copy2(out / 'control.json', destination / 'original-binary.json')
shutil.copy2(out / 'decoder-binary.json', destination / 'current-binary.json')
for name in ['tool.json', 'environment.json', 'release-override.toml']:
    shutil.copy2(destination.parent / 'point-decoder' / name, destination / name)
commands = json.loads((profiles / 'package-evaluate-commands.json').read_text())
for command in commands:
    binary = pathlib.Path(command['command'][-3])
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == command['binary_sha256']
probe = subprocess.run(['perf', 'stat', '-e', 'cycles,instructions', '--', 'true'], capture_output=True, text=True)
(destination / 'perf-probe.json').write_text(json.dumps(dict(
    command=probe.args, exit_code=probe.returncode, stdout=probe.stdout, stderr=probe.stderr,
    limit='Availability probe only. Host settings are unchanged.'), indent=2) + '\n')
record['hardware_counters'] = 'Blocked by host perf_event_paranoid=4.'
files = {}
for path in out.glob('original-gap-*'):
    if path.is_file():
        files['output/' + path.name] = path
for prefix in ['ordinary-control-cycles', 'ordinary-current-cycles', 'result-control-inspect',
               'result-current-inspect', 'package-control-evaluate', 'package-current-evaluate']:
    for path in profiles.glob(prefix + '*'):
        if path.is_file():
            files['callgrind/' + path.name] = path
archive = destination / 'raw-evidence.tar.zst'
compression = ['zstd', '-q', '-T2', '-3', '--long=27', '-o', str(archive)]
process = subprocess.Popen(compression, stdin=subprocess.PIPE)
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
        expected = files[member.name]
        assert member.size == expected.stat().st_size
        with expected.open('rb') as original:
            actual = handle.extractfile(member)
            while chunk := original.read(1 << 20):
                assert actual.read(len(chunk)) == chunk, member.name
            assert not actual.read(1)
    assert names == set(files)
process.stdout.close()
assert process.wait() == 0
record.update(archive_members=len(files), archive_bytes=archive.stat().st_size,
              archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
              archive_members_verified=True, compression_command=compression,
              compression_version=subprocess.check_output(['zstd', '--version'], text=True).strip())
(destination / 'verification.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(destination=str(destination), members=len(files),
                     archive_bytes=archive.stat().st_size,
                     summaries=len(record['summary_checks'])), indent=2), flush=True)
