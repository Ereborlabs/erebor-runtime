import hashlib
import json
import pathlib
import subprocess
import time

directory = pathlib.Path('/tmp/araphor-callgrind')
binary = pathlib.Path('output/storage-engine-baseline-20261108/versioned-header-group')
digest = '514e2ea0e7d7335ce824832f49fb6277ecab81bfece1af8236be0bd650f96533'
assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest
assert not list(directory.glob('wait-current-*'))
command = [
    'strace', '-f', '-qq', '-yy', '-s', '0', '-ttt', '-T',
    '-e', 'trace=write,writev,fsync,fdatasync,lseek,futex',
    '-o', str(directory / 'wait-current-strace.log'),
    str(binary), str(directory / 'wait-current-combined.json'), 'combined',
]
record = dict(command=command, binary_sha256=digest, started_unix_s=time.time(),
              timing_use='Diagnostic only. All traced timing fields excluded from acceptance.',
              sandbox_permissions='require_escalated')
path = directory / 'wait-current-command.json'
path.write_text(json.dumps(record, indent=2) + '\n')
with (directory / 'wait-current-driver.log').open('w') as log:
    process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
record.update(finished_unix_s=time.time(), exit_code=process.returncode)
path.write_text(json.dumps(record, indent=2) + '\n')
print(process.returncode)
assert process.returncode == 0
