import json
import pathlib
import subprocess

directory = pathlib.Path('output/storage-engine-baseline-20261108')
tests = ['--lib']
for name in ['read_view', 'retained_history', 'table_point_reads', 'snapshot_point_read',
             'tree_l0_point_read', 'tree_non_disjoint_point_read', 'tree_disjoint_point_read',
             'expect_point_read_hits']:
    tests += ['--test', name]
checks = [
    ('native', 'lsm-tree', ['test', *tests]),
    ('native-lz4', 'lsm-tree', ['test', '--features', 'lz4', *tests]),
    ('native-clippy', 'lsm-tree', ['clippy', '--lib']),
    ('native-format', 'lsm-tree', ['fmt', '--check']),
    ('cdc', 'fjall', ['test', '--features', 'journal-cdc', '--lib']),
    ('default', 'fjall', ['test', '--lib']),
    ('no-default', 'fjall', ['check', '--no-default-features', '--lib']),
    ('clippy', 'fjall', ['clippy', '--features', 'journal-cdc', '--lib']),
    ('format', 'fjall', ['fmt', '--check']),
]
records = []
for name, tree, args in checks:
    command = ['cargo', args[0], '--manifest-path', tree + '/Cargo.toml', *args[1:]]
    if args[0] != 'fmt':
        command += ['--locked', '--offline']
    path = directory / ('borrow-key-' + name + '.log')
    assert not path.exists()
    with path.open('w') as log:
        process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    records.append(dict(command=command, log=str(path), exit_code=process.returncode))
    (directory / 'borrow-key-gates.json').write_text(json.dumps(records, indent=2) + '\n')
    print(name, process.returncode, flush=True)
    assert process.returncode == 0, name
