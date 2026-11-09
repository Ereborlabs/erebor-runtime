import collections
import json
import pathlib
import re

directory = pathlib.Path('/tmp/araphor-gperftools')
results = {}
for side in ['control', 'current']:
    raw = (directory / (side + '-raw.txt')).read_text()
    sample_text, location_text = raw.split('Locations\n', 1)
    location_text, mappings = location_text.split('Mappings\n', 1)
    assert raw.startswith('PeriodType: cpu nanoseconds\nPeriod: 1000000\n')
    locations = {int(match[1]): int(match[2], 16) for match in re.finditer(
        r'^\s+(\d+): (0x[0-9a-f]+) M=\d+\s*$', location_text, re.M)}
    symbols = (directory / (side + '-symbolized.cpu')).read_bytes().split(b'--- profile\n', 1)[0].decode()
    names = {int(match[1], 16): re.sub(r'<[0-9a-f]{16}>$', '', match[2])
             for match in re.finditer(r'^(0x[0-9a-f]+) (.*)$', symbols, re.M)}
    flat = collections.Counter()
    inclusive = collections.Counter()
    unknown = collections.Counter()
    samples = []
    for match in re.finditer(r'^\s+(\d+)\s+(\d+): (.*)$', sample_text, re.M):
        count, nanoseconds = map(int, match.group(1, 2))
        assert nanoseconds == count * 1000000
        identities = [int(item) for item in match[3].split()]
        assert identities and all(identity in locations for identity in identities)
        addresses = [locations[identity] for identity in identities]
        stack = [names.get(address, hex(address)) for address in addresses]
        missing = [address for address in addresses if address not in names or names[address].startswith('0x')]
        flat[stack[0]] += count
        inclusive.update({name: count for name in set(stack)})
        unknown.update({hex(address): count for address in missing})
        samples.append(dict(count=count, depth=len(stack), unknown_leaf=addresses[0] in missing,
                            unknown_frames=bool(missing), stack=stack))
    total = sum(sample['count'] for sample in samples)
    commands = json.loads((directory / 'commands.json').read_text())
    command = next(command for command in commands if command['side'] == side)
    assert total == command['profiler_interrupts']
    assert sum(flat.values()) == total
    assert any('lsm_tree' in name for name in flat)
    assert any('storage_poc::package::evaluate' in name for name in inclusive)
    results[side] = dict(total_samples=total,
        maximum_depth=max(sample['depth'] for sample in samples),
        unknown_leaf_samples=sum(sample['count'] for sample in samples if sample['unknown_leaf']),
        samples_with_unknown_frames=sum(sample['count'] for sample in samples if sample['unknown_frames']),
        multi_frame_samples=sum(sample['count'] for sample in samples if sample['depth'] > 1),
        flat=dict(flat.most_common()), inclusive=dict(inclusive.most_common()),
        unknown_addresses=dict(unknown), samples=samples)
    print(side, {key: value for key, value in results[side].items() if not isinstance(value, (dict, list))}, flush=True)
    print('native flat', [(name, count) for name, count in flat.most_common() if 'lsm_tree' in name or 'fjall' in name][:12], flush=True)
record = dict(scope='Complete combined driver; all layouts, verification, history, maintenance, and reopen.',
              limits='Process timer, no thread-labelled or unbiased worker CPU attribution. Control historical support differs. Totals are not equal-work performance comparisons. All profiled timings excluded.',
              truncation='Legacy records have no truncation flag. Maximum observed depths are reported; a truncated-sample count is not established.',
              sides=results)
(directory / 'cpu-stacks.json').write_text(json.dumps(record, indent=2) + '\n')
