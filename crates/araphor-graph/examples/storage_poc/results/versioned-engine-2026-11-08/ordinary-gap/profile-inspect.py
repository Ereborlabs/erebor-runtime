import hashlib
import json
import os
import pathlib
import subprocess
import time

directory = pathlib.Path('/tmp/araphor-callgrind')
environment = dict(os.environ, VALGRIND_LIB=str(directory / 'tool/usr/libexec/valgrind'))
target = '<storage_poc::native::Native>::inspect'
records = []
for side, name, digest in [
    ('result-control', 'control', '953f7fd0f4189f50779838026de82505346090d2940b36707636dd6583ab99a8'),
    ('result-current', 'versioned-direct-decoder', 'd4f84259d53519011f19775802991b72f750723614be9ef4a795e86a9963d31a'),
]:
    assert not list(directory.glob(side + '-inspect*'))
    binary = pathlib.Path('output/storage-engine-baseline-20261108') / name
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest
    command = [
        str(directory / 'tool/usr/bin/valgrind'), '--tool=callgrind',
        '--enable-debuginfod=no', '--vgdb=no', '--collect-atstart=no',
        '--toggle-collect=' + target, '--zero-before=' + target, '--dump-after=' + target,
        '--separate-threads=yes', '--separate-callers=8',
        '--callgrind-out-file=' + str(directory / (side + '-inspect.out')),
        '--log-file=' + str(directory / (side + '-inspect-valgrind.log')),
        str(binary), str(directory / (side + '-inspect-combined.json')), 'combined',
    ]
    record = dict(side=side, command=command, started_unix_s=time.time(),
                  binary_sha256=digest, environment={'VALGRIND_LIB': environment['VALGRIND_LIB']},
                  timing_use='Diagnostic only. All profiled timing fields excluded from acceptance.')
    records.append(record)
    path = directory / 'result-inspect-commands.json'
    path.write_text(json.dumps(records, indent=2) + '\n')
    with (directory / (side + '-inspect-driver.log')).open('w') as log:
        process = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
    record.update(finished_unix_s=time.time(), exit_code=process.returncode)
    path.write_text(json.dumps(records, indent=2) + '\n')
    print(side, process.returncode, flush=True)
    assert process.returncode == 0
