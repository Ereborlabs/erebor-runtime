import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import time

directory = pathlib.Path('/tmp/araphor-gperftools')
library = directory / 'tool/usr/lib/x86_64-linux-gnu/libprofiler.so.0.5.11'
spec = importlib.util.spec_from_file_location(
    'summarize_cdc', 'crates/araphor-graph/examples/storage_poc/summarize_cdc.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
records = []
for name in ['LD_PRELOAD', 'CPUPROFILE', 'CPUPROFILE_REALTIME',
             'CPUPROFILE_PER_THREAD_TIMERS', 'CPUPROFILE_TIMER_SIGNAL', 'CPUPROFILESIGNAL']:
    assert name not in os.environ, name
for side, name, digest in [
    ('control', 'control', '953f7fd0f4189f50779838026de82505346090d2940b36707636dd6583ab99a8'),
    ('current', 'versioned-direct-decoder', 'd4f84259d53519011f19775802991b72f750723614be9ef4a795e86a9963d31a'),
]:
    binary = (pathlib.Path('output/storage-engine-baseline-20261108') / name).resolve()
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest
    report = directory / (side + '-combined.json')
    profile = directory / (side + '.cpu')
    assert not profile.exists() and not report.exists()
    extra = dict(LD_PRELOAD=str(library), CPUPROFILE=str(profile), CPUPROFILE_FREQUENCY='1000')
    command = [str(binary), str(report), 'combined']
    record = dict(side=side, command=command, environment=extra,
                  binary_sha256=digest, library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                  started_unix_s=time.time(),
                  scope='Complete unchanged combined driver, including all layouts and stages.',
                  limits='Process-wide CPU timer; no thread labels or unbiased per-thread coverage. All profiled timings excluded.')
    records.append(record)
    (directory / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
    with (directory / (side + '-driver.log')).open('w') as log:
        result = subprocess.run(command, env=dict(os.environ, **extra), stdout=log, stderr=subprocess.STDOUT)
    record.update(finished_unix_s=time.time(), exit_code=result.returncode)
    (directory / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
    assert result.returncode == 0
    summary = module.summarize(json.loads(report.read_text()))
    (directory / (side + '-summary.json')).write_text(json.dumps(summary, indent=2) + '\n')
    log = (directory / (side + '-driver.log')).read_text()
    counts = re.search(r'PROFILE: interrupts/evictions/bytes = (\d+)/(\d+)/(\d+)', log)
    assert counts and int(counts[1]) > 0, log
    for mode in ['raw', 'top']:
        command = ['go', 'tool', 'pprof', '-' + mode, '-symbolize=local']
        if mode == 'top':
            command.extend(['-nodecount=80', '-unit=ms'])
        command.extend([str(binary), str(profile)])
        result = subprocess.run(command, capture_output=True, text=True)
        (directory / (side + '-' + mode + '.txt')).write_text(result.stdout)
        (directory / (side + '-' + mode + '-stderr.txt')).write_text(result.stderr)
        assert result.returncode == 0, result.stderr
        record[mode + '_command'] = command
    record['profiler_interrupts'] = int(counts[1])
    record['profile_bytes'] = profile.stat().st_size
    (directory / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
    print(side, record['profiler_interrupts'], record['profile_bytes'], flush=True)
