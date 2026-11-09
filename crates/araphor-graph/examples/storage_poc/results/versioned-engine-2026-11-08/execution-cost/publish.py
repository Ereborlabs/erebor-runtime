import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess
import tarfile

base = pathlib.Path('crates/araphor-graph/examples/storage_poc')
out = pathlib.Path('output/storage-engine-baseline-20261108')
cache = pathlib.Path('/tmp/araphor-callgrind')
cpu = pathlib.Path('/tmp/araphor-gperftools')
destination = base / 'results/versioned-engine-2026-11-08/execution-cost'
destination.mkdir(exist_ok=False)
spec = importlib.util.spec_from_file_location('summarize_cdc', base / 'summarize_cdc.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
record = dict(performance='Not done', source_changes=False, summary_checks=[])
events = json.loads((cache / 'cache-package-events.json').read_text())
record['ordinary_package'] = dict(scope=events['scope'], limits=events['limits'],
    cache_model=events['cache_model'], change_percent=events['change_percent'],
    sides={side: dict(samples=result['ordinary_samples'], totals=result['totals'],
                     zero_residual_and_worker_profiles=result['zero_residual_and_worker_profiles'])
           for side, result in events['sides'].items()})
stacks = json.loads((cpu / 'cpu-stacks.json').read_text())
record['whole_driver_cpu'] = {key: value for key, value in stacks.items() if key != 'sides'}
record['whole_driver_cpu']['sides'] = {
    side: {key: value for key, value in result.items() if not isinstance(value, (dict, list))}
    for side, result in stacks['sides'].items()}
for directory, prefixes in [(cache, ['cache-control-package-', 'cache-current-package-']),
                             (cpu, ['control-', 'current-'])]:
    for prefix in prefixes:
        report = directory / (prefix + 'combined.json')
        assert module.summarize(json.loads(report.read_text())) == json.loads(
            (directory / (prefix + 'summary.json')).read_text())
        record['summary_checks'].append(report.name)
for filename, digest in [('control', '953f7fd0f4189f50779838026de82505346090d2940b36707636dd6583ab99a8'),
                         ('versioned-direct-decoder', 'd4f84259d53519011f19775802991b72f750723614be9ef4a795e86a9963d31a')]:
    assert hashlib.sha256((out / filename).read_bytes()).hexdigest() == digest
for source, name in [('/tmp/araphor-cache-profiles.py', 'profile-cache.py'),
                     (str(cache / 'analyze-cache.py'), 'analyze-cache.py'),
                     ('/tmp/araphor-cpu-profiles.py', 'profile-cpu.py'),
                     ('/tmp/araphor-symbolize-cpu.py', 'symbolize-cpu.py'),
                     ('/tmp/araphor-analyze-cpu.py', 'analyze-cpu.py'),
                     ('/tmp/araphor-publish-cost.py', 'publish.py')]:
    shutil.copy2(source, destination / name)
for source, name in [(cache / 'cache-package-commands.json', 'cache-commands.json'),
                     (cache / 'perf-host-probe.json', 'perf-host-probe.json'),
                     (cpu / 'commands.json', 'cpu-commands.json'),
                     (cpu / 'symbolize-commands.json', 'symbolize-commands.json'),
                     (out / 'control.json', 'original-binary.json'),
                     (out / 'decoder-binary.json', 'current-binary.json')]:
    shutil.copy2(source, destination / name)
for name in ['tool.json', 'environment.json', 'release-override.toml']:
    shutil.copy2(destination.parent / 'point-decoder' / name, destination / name)
geometry = pathlib.Path('/sys/devices/system/cpu/cpu0/cache')
record['host_cache_geometry'] = {
    index.name: {name: (index / name).read_text().strip() for name in
                 ['level', 'type', 'size', 'coherency_line_size', 'ways_of_associativity', 'number_of_sets']}
    for index in geometry.glob('index*')}
library = cpu / 'tool/usr/lib/x86_64-linux-gnu/libprofiler.so.0.5.11'
linked = subprocess.check_output(['ldd', str(library)], text=True)
dependencies = [pathlib.Path(path) for path in re.findall(r'=> (/\S+)', linked)]
record['profiler_tool'] = dict(packages={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
    for path in cpu.glob('*.deb')}, library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
    reader_sha256=hashlib.sha256((cpu / 'tool/usr/bin/google-pprof').read_bytes()).hexdigest(),
    linked_libraries=linked, dependency_sha256={str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                                             for path in dependencies},
    go_version=subprocess.check_output(['go', 'version'], text=True).strip(),
    sampling='Default process-wide ITIMER_PROF; 1000 Hz. Only libprofiler is preloaded.')
files = {}
for pattern in ['cache-control-package*', 'cache-current-package*', 'cache-package-events.json',
                'gprofng-*probe*', 'gprofng-dispatcher-2_42.*', 'gprofng-dispatcher-2_45.*']:
    for path in cache.glob(pattern):
        if path.is_file():
            files['callgrind/' + path.name] = path
        elif path.is_dir():
            for child in path.rglob('*'):
                if child.is_file():
                    files['callgrind/' + str(child.relative_to(cache))] = child
for path in cpu.iterdir():
    if path.is_file():
        files['cpu/' + path.name] = path
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
              archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
              archive_members_verified=True, compression_command=command)
(destination / 'verification.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(destination=str(destination), members=len(files), bytes=archive.stat().st_size), indent=2))
