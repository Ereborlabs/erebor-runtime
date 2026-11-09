import hashlib
import json
import os
import pathlib
import subprocess
import time

directory = pathlib.Path('/tmp/araphor-callgrind')
outputs = pathlib.Path('output/storage-engine-baseline-20261108')
cases = [
    ('apply-control', 'control', '953f7fd0f4189f50779838026de82505346090d2940b36707636dd6583ab99a8'),
    ('apply-current', 'versioned-header-group', '514e2ea0e7d7335ce824832f49fb6277ecab81bfece1af8236be0bd650f96533'),
]
for side, name, digest in cases:
    assert not list(directory.glob(side + '-*')), side
    assert hashlib.sha256((outputs / name).read_bytes()).hexdigest() == digest, name
environment = dict(os.environ, VALGRIND_LIB=str(directory / 'tool/usr/libexec/valgrind'))
for side, name, digest in cases:
    command = [
        str(directory / 'tool/usr/bin/valgrind'), '--tool=callgrind',
        '--enable-debuginfod=no', '--vgdb=no', '--collect-atstart=no',
        '--toggle-collect=<storage_poc::native::Native>::apply_saved',
        '--separate-threads=yes', '--separate-callers=8',
        '--callgrind-out-file=' + str(directory / (side + '-profile.out')),
        '--log-file=' + str(directory / (side + '-valgrind.log')),
        str(outputs / name), str(directory / (side + '-combined.json')), 'combined',
    ]
    record = dict(command=command, environment={'VALGRIND_LIB': environment['VALGRIND_LIB']},
                  binary_sha256=digest, started_unix_s=time.time(),
                  metric='Instructions inside actual Native::apply_saved calls across both layouts.',
                  timing_use='Diagnostic only. All profiled timing fields excluded from acceptance.')
    path = directory / (side + '-command.json')
    path.write_text(json.dumps(record, indent=2) + '\n')
    print('start', side, flush=True)
    with (directory / (side + '-driver.log')).open('w') as log:
        process = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
    record.update(finished_unix_s=time.time(), exit_code=process.returncode)
    path.write_text(json.dumps(record, indent=2) + '\n')
    print('finish', side, process.returncode, flush=True)
    assert process.returncode == 0, side
