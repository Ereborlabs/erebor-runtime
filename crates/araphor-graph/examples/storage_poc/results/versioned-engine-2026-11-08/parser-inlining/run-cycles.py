import hashlib
import json
import os
import pathlib
import subprocess
import time

directory = pathlib.Path('/tmp/araphor-callgrind')
tool = directory / 'tool/usr/bin/valgrind'
environment = dict(os.environ, VALGRIND_LIB=str(directory / 'tool/usr/libexec/valgrind'))
record = []
for side, name in [('control', 'control'), ('current', 'versioned-direct-compression')]:
    binary = pathlib.Path('output/storage-engine-baseline-20261108') / name
    command = [
        str(tool), '--tool=callgrind', '--enable-debuginfod=no', '--vgdb=no',
        '--collect-atstart=no', '--toggle-collect=*native*View*query*',
        '--toggle-collect=*native*View*presence*', '--separate-threads=yes',
        '--separate-callers=8', '--zero-before=storage_poc::package::evaluate',
        '--dump-after=storage_poc::package::evaluate',
        f'--callgrind-out-file={directory / (side + "-cycles.out")}',
        f'--log-file={directory / (side + "-cycles-valgrind.log")}',
        str(binary), str(directory / (side + '-cycles-combined.json')), 'combined',
    ]
    started = time.time()
    with (directory / (side + '-cycles-driver.log')).open('w') as log:
        result = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
    record.append({
        'side': side, 'command': command, 'started_unix_s': started,
        'finished_unix_s': time.time(), 'exit_code': result.returncode,
        'binary_sha256': hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest(),
        'timing_use': 'diagnostic only; excluded from acceptance',
    })
    (directory / 'cycle-commands.json').write_text(json.dumps(record, indent=2) + '\n')
    print(side, 'exit', result.returncode, flush=True)
    result.check_returncode()
