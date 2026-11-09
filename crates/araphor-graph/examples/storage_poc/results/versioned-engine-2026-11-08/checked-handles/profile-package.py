import hashlib
import json
import os
import pathlib
import subprocess
import time

directory = pathlib.Path('/tmp/araphor-callgrind')
manifest = json.loads(pathlib.Path('output/storage-engine-baseline-20261108/checked-handle-binary.json').read_text())
environment = dict(os.environ, VALGRIND_LIB=str(directory / 'tool/usr/libexec/valgrind'))
target = 'storage_poc::package::evaluate'
records = []
for side in ['before', 'after']:
    prefix = 'checked-handle-' + side + '-package'
    assert not list(directory.glob(prefix + '*'))
    binary = pathlib.Path(manifest['before_binary'] if side == 'before' else manifest['binary'])
    digest = manifest['before_binary_sha256'] if side == 'before' else manifest['binary_sha256']
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest
    command = [str(directory / 'tool/usr/bin/valgrind'), '--tool=callgrind',
               '--enable-debuginfod=no', '--vgdb=no', '--collect-atstart=no',
               '--toggle-collect=' + target, '--zero-before=' + target,
               '--dump-after=' + target, '--separate-threads=yes', '--separate-callers=8',
               '--callgrind-out-file=' + str(directory / (prefix + '.out')),
               '--log-file=' + str(directory / (prefix + '-valgrind.log')),
               str(binary), str(directory / (prefix + '-combined.json')), 'combined']
    record = dict(side=side, command=command, binary_sha256=digest,
                  environment={'VALGRIND_LIB': environment['VALGRIND_LIB']},
                  started_unix_s=time.time(),
                  scope='Complete actual package evaluations; exact native Table::get incoming costs and calls remain nested.',
                  limits='Instructions only. All profiled timings excluded.')
    records.append(record)
    (directory / 'checked-handle-package-commands.json').write_text(json.dumps(records, indent=2) + '\n')
    with (directory / (prefix + '-driver.log')).open('w') as log:
        process = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
    record.update(finished_unix_s=time.time(), exit_code=process.returncode)
    (directory / 'checked-handle-package-commands.json').write_text(json.dumps(records, indent=2) + '\n')
    print(side, process.returncode, flush=True)
    assert process.returncode == 0
