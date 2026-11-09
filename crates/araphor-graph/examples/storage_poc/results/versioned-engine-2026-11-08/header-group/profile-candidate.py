import hashlib
import json
import os
import pathlib
import subprocess
import time

directory = pathlib.Path('/tmp/araphor-callgrind')
binary = pathlib.Path('output/storage-engine-baseline-20261108/versioned-header-group')
digest = '514e2ea0e7d7335ce824832f49fb6277ecab81bfece1af8236be0bd650f96533'
assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest
assert not list(directory.glob('header-cdc-*'))
command = [
    str(directory / 'tool/usr/bin/valgrind'), '--tool=callgrind',
    '--enable-debuginfod=no', '--vgdb=no', '--collect-atstart=no',
    '--toggle-collect=<fjall::cdc::Feed>::next_batch',
    '--separate-threads=yes', '--separate-callers=8',
    '--callgrind-out-file=' + str(directory / 'header-cdc-profile.out'),
    '--log-file=' + str(directory / 'header-cdc-valgrind.log'),
    str(binary), str(directory / 'header-cdc-combined.json'), 'combined',
]
environment = dict(os.environ, VALGRIND_LIB=str(directory / 'tool/usr/libexec/valgrind'))
record = dict(command=command, environment={'VALGRIND_LIB': environment['VALGRIND_LIB']},
              binary_sha256=digest, started_unix_s=time.time(),
              timing_use='Diagnostic only; all profiled timing fields excluded from acceptance.')
path = directory / 'header-cdc-command.json'
path.write_text(json.dumps(record, indent=2) + '\n')
with (directory / 'header-cdc-driver.log').open('w') as log:
    process = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
record.update(finished_unix_s=time.time(), exit_code=process.returncode)
path.write_text(json.dumps(record, indent=2) + '\n')
print(process.returncode)
assert process.returncode == 0
