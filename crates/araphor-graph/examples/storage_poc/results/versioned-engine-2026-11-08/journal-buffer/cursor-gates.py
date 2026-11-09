import json
import pathlib
import subprocess

directory = pathlib.Path('output/storage-engine-baseline-20261108')
records = []
for name, args in [
    ('cdc', ['test', '--features', 'journal-cdc']),
    ('default', ['test']),
    ('no-default', ['check', '--no-default-features']),
    ('clippy', ['clippy', '--features', 'journal-cdc']),
    ('format', ['fmt', '--check']),
]:
    command = ['cargo', args[0], '--manifest-path', 'fjall/Cargo.toml', *args[1:]]
    if args[0] != 'fmt':
        command += ['--lib', '--locked', '--offline']
    path = directory / ('cursor-buffer-' + name + '.log')
    with path.open('w') as log:
        process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    records.append(dict(command=command, log=str(path), exit_code=process.returncode))
    (directory / 'cursor-buffer-gates.json').write_text(json.dumps(records, indent=2) + '\n')
    print(name, process.returncode, flush=True)
    assert process.returncode == 0, name
