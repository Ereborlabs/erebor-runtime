import hashlib
import json
import os
import pathlib
import subprocess
import time

directory = pathlib.Path('/tmp/araphor-callgrind')
binary = pathlib.Path('output/storage-engine-baseline-20261108/versioned-cursor-buffer')
digest = '49c6b10d8e4f349033e6aa30f307e3175b5270a069bb7bd2646904a92b8792e3'
assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest
assert not list(directory.glob('apply-cursor-*'))
command = [
    str(directory / 'tool/usr/bin/valgrind'), '--tool=callgrind',
    '--enable-debuginfod=no', '--vgdb=no', '--collect-atstart=no',
    '--toggle-collect=<storage_poc::native::Native>::apply_saved',
    '--separate-threads=yes', '--separate-callers=8',
    '--callgrind-out-file=' + str(directory / 'apply-cursor-profile.out'),
    '--log-file=' + str(directory / 'apply-cursor-valgrind.log'),
    str(binary), str(directory / 'apply-cursor-combined.json'), 'combined',
]
environment = dict(os.environ, VALGRIND_LIB=str(directory / 'tool/usr/libexec/valgrind'))
record = dict(command=command, environment={'VALGRIND_LIB': environment['VALGRIND_LIB']},
              binary_sha256=digest, started_unix_s=time.time(),
              timing_use='Diagnostic only. All profiled timing fields excluded from acceptance.')
path = directory / 'apply-cursor-command.json'
path.write_text(json.dumps(record, indent=2) + '\n')
with (directory / 'apply-cursor-driver.log').open('w') as log:
    process = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
record.update(finished_unix_s=time.time(), exit_code=process.returncode)
path.write_text(json.dumps(record, indent=2) + '\n')
print(process.returncode)
assert process.returncode == 0
