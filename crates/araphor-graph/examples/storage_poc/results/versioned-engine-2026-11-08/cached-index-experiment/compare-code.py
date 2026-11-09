import collections
import hashlib
import json
import pathlib
import struct
import subprocess

directory = pathlib.Path('output/storage-engine-baseline-20261108')
paths = [directory / 'versioned-cached-index', directory / 'versioned-cached-inline']


def sections(path):
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01'
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    offset, entry_size, count, names_index = header[6], header[11], header[12], header[13]
    rows = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * entry_size) for i in range(count)]
    names = data[rows[names_index][4]:rows[names_index][4] + rows[names_index][5]]
    result = {}
    for row in rows:
        name = names[row[0]:].split(b'\0', 1)[0].decode()
        if name in ['.text', '.rodata']:
            result[name] = (row[3], data[row[4]:row[4] + row[5]])
    return result


symbols = []
for line in subprocess.check_output(['nm', '-n', '-S', '--defined-only', '--demangle', str(paths[1])], text=True).splitlines():
    parts = line.split(maxsplit=3)
    if len(parts) == 4 and parts[2] in ['t', 'T']:
        symbols.append((int(parts[0], 16), int(parts[1], 16), parts[3]))

before, after = [sections(path) for path in paths]
result = {}
for name in before:
    a, b = before[name][1], after[name][1]
    assert len(a) == len(b)
    changed = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
    record = dict(before_sha256=hashlib.sha256(a).hexdigest(), after_sha256=hashlib.sha256(b).hexdigest(),
                  bytes=len(a), changed_bytes=len(changed))
    if name == '.text':
        counts = collections.Counter()
        for position in changed:
            address = after[name][0] + position
            owners = {symbol for start, size, symbol in symbols if start <= address < start + size}
            assert owners, position
            for symbol in owners:
                counts[symbol] += 1
        assert sum(counts.values()) == len(changed)
        assert all(symbol.startswith(('storage_poc::', '<storage_poc::')) for symbol in counts)
        record.update(all_changed_text_bytes_covered=True, changed_functions=dict(counts))
    result[name] = record

(directory / 'cached-inline-code-comparison.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
