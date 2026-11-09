import hashlib
import json
import os
import pathlib
import subprocess
import time

directory = pathlib.Path('/tmp/araphor-callgrind')
binary = pathlib.Path('output/storage-engine-baseline-20261108/versioned-direct-decoder')
digest = 'd4f84259d53519011f19775802991b72f750723614be9ef4a795e86a9963d31a'
assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest
assert not list(directory.glob('point-native-after-*'))
command = [
    str(directory / 'tool/usr/bin/valgrind'), '--tool=callgrind',
    '--enable-debuginfod=no', '--vgdb=no', '--collect-atstart=no',
    '--toggle-collect=<lsm_tree::table::data_block::DataBlock>::point_read',
    '--separate-threads=yes', '--separate-callers=12',
    '--callgrind-out-file=' + str(directory / 'point-native-after-profile.out'),
    '--log-file=' + str(directory / 'point-native-after-valgrind.log'),
    str(binary), str(directory / 'point-native-after-combined.json'), 'combined',
]
environment = dict(os.environ, VALGRIND_LIB=str(directory / 'tool/usr/libexec/valgrind'))
record = dict(command=command, environment={'VALGRIND_LIB': environment['VALGRIND_LIB']},
              binary_sha256=digest, started_unix_s=time.time(),
              timing_use='Diagnostic only. All profiled timing fields excluded from acceptance.')
path = directory / 'point-native-after-command.json'
path.write_text(json.dumps(record, indent=2) + '\n')
with (directory / 'point-native-after-driver.log').open('w') as log:
    process = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
record.update(finished_unix_s=time.time(), exit_code=process.returncode)
path.write_text(json.dumps(record, indent=2) + '\n')
print(process.returncode)
assert process.returncode == 0
