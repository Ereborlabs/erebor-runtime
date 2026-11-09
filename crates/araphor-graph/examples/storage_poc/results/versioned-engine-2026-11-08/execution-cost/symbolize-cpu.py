import json
import os
import pathlib
import subprocess

directory = pathlib.Path('/tmp/araphor-gperftools')
tool = directory / 'tool/usr/bin/google-pprof'
environment = dict(os.environ, PPROF_TMPDIR=str(directory / 'reader-tmp'))
records = []
for side, name in [('control', 'control'), ('current', 'versioned-direct-decoder')]:
    binary = (pathlib.Path('output/storage-engine-baseline-20261108') / name).resolve()
    command = [str(tool), '--raw', '--no_strip_temp', str(binary), str(directory / (side + '.cpu'))]
    result = subprocess.run(command, env=environment, capture_output=True)
    raw = directory / (side + '-symbolized.cpu')
    raw.write_bytes(result.stdout)
    (directory / (side + '-symbolize-stderr.txt')).write_bytes(result.stderr)
    assert result.returncode == 0 and raw.stat().st_size > 0
    records.append(dict(command=command, environment={'PPROF_TMPDIR': environment['PPROF_TMPDIR']},
                        exit_code=result.returncode))
    for mode in ['text']:
        command = [str(tool), '--' + mode, '--no_strip_temp', str(binary), str(directory / (side + '.cpu'))]
        result = subprocess.run(command, capture_output=True, text=True)
        (directory / (side + '-symbolized-' + mode + '.txt')).write_text(result.stdout)
        (directory / (side + '-symbolized-' + mode + '-stderr.txt')).write_text(result.stderr)
        assert result.returncode == 0, result.stderr
        records.append(dict(command=command, exit_code=result.returncode))
    print(side, raw.stat().st_size, flush=True)
(directory / 'symbolize-commands.json').write_text(json.dumps(records, indent=2) + '\n')
