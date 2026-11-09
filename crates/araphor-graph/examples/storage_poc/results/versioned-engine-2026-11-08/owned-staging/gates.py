import json
import pathlib
import subprocess

directory = pathlib.Path('output/storage-engine-baseline-20261108')
checks = [
    ('cdc', ['test', '--features', 'journal-cdc', '--lib']),
    ('default', ['test', '--lib']),
    ('no-default', ['check', '--no-default-features', '--lib']),
    ('clippy', ['clippy', '--features', 'journal-cdc', '--lib']),
    ('format', ['fmt', '--check']),
]
records = []
for name, args in checks:
    command = ['cargo', args[0], '--manifest-path', 'fjall/Cargo.toml', *args[1:]]
    if args[0] != 'fmt':
        command += ['--locked', '--offline']
    path = directory / ('consume-' + name + '.log')
    assert not path.exists()
    with path.open('w') as log:
        process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    records.append(dict(command=command, log=str(path), exit_code=process.returncode))
    (directory / 'consume-gates.json').write_text(json.dumps(records, indent=2) + '\n')
    print(name, process.returncode, flush=True)
    assert process.returncode == 0, name
