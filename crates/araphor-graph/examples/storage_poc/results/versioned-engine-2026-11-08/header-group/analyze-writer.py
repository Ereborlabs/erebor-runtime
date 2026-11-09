import collections
import importlib.util
import json
import pathlib
import re

directory = pathlib.Path('/tmp/araphor-callgrind')
base = pathlib.Path('crates/araphor-graph/examples/storage_poc')
spec = importlib.util.spec_from_file_location('summarize_cdc', base / 'summarize_cdc.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
target = '<fjall::journal::writer::Writer>::write_batch::<core::slice::iter::Iter<fjall::batch::item::Item>>'
exclusive = collections.Counter()
inclusive = collections.Counter()
calls = collections.Counter()
profiles = []
for path in sorted(directory.glob('writer-current-profile.out-*')):
    lines = path.read_text().splitlines()
    assert 'positions: line' in lines and 'events: Ir' in lines
    names = {m[1]: m[2] for line in lines if (m := re.match(r'c?fn=\((\d+)\) (.+)', line))}
    own = called = ''
    pending = False
    costs = collections.Counter()
    for line in lines:
        if m := re.match(r'(c?)fn=\((\d+)\)', line):
            if m[1]:
                called = names[m[2]].split("'", 1)[0]
            else:
                own = names[m[2]].split("'", 1)[0]
                pending = False
        elif line.startswith('calls='):
            calls[called] += int(line.split()[0].split('=')[1])
            pending = True
        elif m := re.match(r'^(?:\d+|\*|[+-]\d+)\s+(\d+)\s*$', line):
            if pending:
                inclusive[called] += int(m[1])
                pending = False
            else:
                costs[own] += int(m[1])
    header = int(next(line.split()[1] for line in lines if line.startswith('summary:')))
    total = int(next(line.split()[1] for line in lines if line.startswith('totals:')))
    assert header == total == sum(costs.values()), path.name
    if not path.name.endswith('-01'):
        assert total == 0
    exclusive.update(costs)
    profiles.append(dict(profile=path.name, instructions=total))
assert calls[target] > 0 and inclusive[target] == sum(exclusive.values())
checks = []
for name in ['callgrind', 'strace-allowed']:
    path = directory / ('writer-current-' + name + '-combined.json')
    summary = module.summarize(json.loads(path.read_text()))
    path.with_name(path.stem + '-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    checks.append(path.name)
pending = {}
syscalls = collections.Counter()
writes = collections.Counter()
by_file = {}
completed = 0
for line in (directory / 'writer-current-strace-allowed.log').read_text().splitlines():
    match = re.match(r'^(\d+)\s+(.*)', line)
    assert match, line
    thread, body = match.groups()
    if '<unfinished ...>' in body:
        assert thread not in pending
        pending[thread] = body.split('<unfinished ...>', 1)[0]
        continue
    if match := re.match(r'^<\.\.\. \w+ resumed>(.*)', body):
        body = pending.pop(thread) + match[1]
    if body.startswith(('+++', '---')):
        continue
    match = re.match(r'^(write|writev|fsync|fdatasync|lseek)\((.*?)\)\s+=\s+(-?\d+)', body)
    assert match, body
    operation, arguments, returned = match.groups()
    completed += 1
    descriptor = re.match(r'^\d+<([^>]+)>', arguments)
    if not descriptor or not descriptor[1].endswith('.jnl'):
        continue
    assert int(returned) >= 0, body
    path = descriptor[1]
    syscalls[operation] += 1
    values = by_file.setdefault(path, collections.Counter())
    values[operation] += 1
    if operation in ['write', 'writev']:
        size = int(returned)
        writes[size] += 1
        values['written_bytes'] += size
assert not pending
result = dict(
    scope='Existing full combined driver; all layouts and threads; all profiled timings excluded.',
    summary_checks=checks,
    writer=dict(instructions=sum(exclusive.values()), calls=calls[target], profiles=profiles,
                exclusive=dict(exclusive.most_common()), inclusive=dict(inclusive.most_common()), calls_by_function=dict(calls)),
    journal_syscalls=dict(syscalls), journal_write_sizes=dict(sorted(writes.items())),
    journal_files={path: dict(values) for path, values in by_file.items()},
    all_completed_trace_calls=completed,
)
(directory / 'writer-diagnostic.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({k: v for k, v in result.items() if k not in ['writer', 'journal_files']}, indent=2))
print('Writer', result['writer']['instructions'], result['writer']['calls'])
print('Top exclusive', list(exclusive.most_common(12)))
