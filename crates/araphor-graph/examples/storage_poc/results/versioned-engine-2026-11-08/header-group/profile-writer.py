import hashlib
import json
import os
import pathlib
import subprocess
import time

directory = pathlib.Path('/tmp/araphor-callgrind')
binary = pathlib.Path('output/storage-engine-baseline-20261108/versioned-checksum-buffered')
digest = '69847bb15f668eec5a53c0b00b16ce3f23c31b895429bcae0f029dd39aaefc4b'
assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest
assert not list(directory.glob('writer-current-*'))
environment = dict(os.environ, VALGRIND_LIB=str(directory / 'tool/usr/libexec/valgrind'))
cases = [
    ('callgrind', [
        str(directory / 'tool/usr/bin/valgrind'), '--tool=callgrind',
        '--enable-debuginfod=no', '--vgdb=no', '--collect-atstart=no',
        '--toggle-collect=<fjall::journal::writer::Writer>::write_batch::<core::slice::iter::Iter<fjall::batch::item::Item>>',
        '--separate-threads=yes', '--separate-callers=8',
        '--callgrind-out-file=' + str(directory / 'writer-current-profile.out'),
        '--log-file=' + str(directory / 'writer-current-valgrind.log'),
    ]),
    ('strace', [
        'strace', '-f', '-qq', '-yy', '-s', '0',
        '-e', 'trace=write,writev,fsync,fdatasync,lseek',
        '-o', str(directory / 'writer-current-strace.log'),
    ]),
]
for name, prefix in cases:
    command = [*prefix, str(binary), str(directory / ('writer-current-' + name + '-combined.json')), 'combined']
    record = dict(command=command, binary_sha256=digest, started_unix_s=time.time(),
                  environment={'VALGRIND_LIB': environment['VALGRIND_LIB']},
                  timing_use='Diagnostic only; all profiled timing fields excluded from acceptance.')
    path = directory / ('writer-current-' + name + '-command.json')
    path.write_text(json.dumps(record, indent=2) + '\n')
    print('start', name, flush=True)
    with (directory / ('writer-current-' + name + '-driver.log')).open('w') as log:
        process = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
    record.update(finished_unix_s=time.time(), exit_code=process.returncode)
    path.write_text(json.dumps(record, indent=2) + '\n')
    print('finish', name, process.returncode, flush=True)
    assert process.returncode == 0, name
