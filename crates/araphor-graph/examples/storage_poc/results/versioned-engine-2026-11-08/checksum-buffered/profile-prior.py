import hashlib
import json
import os
import pathlib
import subprocess
import time

root = pathlib.Path('/home/navid/go/src/github.com/Ereborlabs/erebor-runtime')
directory = pathlib.Path('/tmp/araphor-callgrind')
outputs = root / 'output/storage-engine-baseline-20261108'
cases = [
    ('control-cdc', 'control', '953f7fd0f4189f50779838026de82505346090d2940b36707636dd6583ab99a8', '<fjall::cdc::Feed>::read'),
    ('inline-cdc', 'versioned-inline-parser', '0cad41c8fba195f62e32f5b9f0833a41592391c7eaaa0e3b43593d1b8bf4fe47', '<fjall::cdc::Feed>::next_batch'),
]
for side, name, digest, target in cases:
    assert not list(directory.glob(side + '-*')), side
    assert hashlib.sha256((outputs / name).read_bytes()).hexdigest() == digest, name
environment = dict(os.environ, VALGRIND_LIB=str(directory / 'tool/usr/libexec/valgrind'))
for side, name, digest, target in cases:
    command = [
        str(directory / 'tool/usr/bin/valgrind'), '--tool=callgrind',
        '--enable-debuginfod=no', '--vgdb=no', '--collect-atstart=no',
        '--toggle-collect=' + target, '--separate-threads=yes', '--separate-callers=8',
        '--callgrind-out-file=' + str(directory / (side + '-profile.out')),
        '--log-file=' + str(directory / (side + '-valgrind.log')),
        str(outputs / name), str(directory / (side + '-combined.json')), 'combined',
    ]
    record = {
        'command': command, 'environment': {'VALGRIND_LIB': environment['VALGRIND_LIB']},
        'binary_sha256': digest, 'started_unix_s': time.time(),
        'metric': 'Executed instructions inside native feed calls; all threads and both layouts.',
        'timing_use': 'Diagnostic only; all profiled timing fields excluded from acceptance.',
    }
    manifest = directory / (side + '-command.json')
    manifest.write_text(json.dumps(record, indent=2) + '\n')
    print('start', side, flush=True)
    with (directory / (side + '-driver.log')).open('w') as log:
        process = subprocess.run(command, cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT)
    record.update(finished_unix_s=time.time(), exit_code=process.returncode)
    manifest.write_text(json.dumps(record, indent=2) + '\n')
    print('finish', side, process.returncode, flush=True)
    assert process.returncode == 0, side
