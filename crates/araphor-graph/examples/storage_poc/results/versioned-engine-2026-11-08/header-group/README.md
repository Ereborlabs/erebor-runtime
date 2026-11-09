# Native journal Item header reads

Fjall `ee3ea07` reads the four fixed Item fields in one 18-byte stack buffer.
The existing native little-endian decoder reads that buffer. Value and
compression tags are still checked first. Key and value decoding follow the
header. The stored format, checksum bytes, public APIs, and durability remain.
The change removes three checksum updates per Item without a new parser or
heap allocation. Only `fjall/src/journal/entry.rs` changes. `lsm-tree` remains
at `aed3e47a`.

The reviewer and implementer agreed on the design before the edit. They
accepted the measured feed CPU reduction after independent review of the
source and raw evidence. They did not accept a latency gain. The
[source patch](source.patch) starts at Fjall `f72bd21`. The
[binary manifest](binary.json) identifies both frozen executables and the
exact patch. No PoC workload, execution order, assertion, timing boundary,
durability, or summary calculation changes.

## Measured native feed work

Callgrind 3.22.0 collects native feed calls across all workers and both key
layouts in the complete existing combined driver. All profiled timings are
excluded from acceptance. These are not ordinary-cycle or per-layout counts.

| Recorded work | Before | After |
| --- | ---: | ---: |
| Feed instructions | 56,262,749 | 49,143,165 |
| Feed calls and decoded batches | 216 | 216 |
| Decoded items | 14,264 | 14,264 |
| Journal bytes | 3,046,976 | 3,046,976 |
| Source wakes / Graph wakes | 64 / 64 | 64 / 64 |
| Checksum update calls | 130,580 | 87,144 |

Feed instructions decrease by **12.654%**. Each raw profile header, exclusive
instruction sum, and incoming feed cost agree. The main thread collects zero
instructions. LZ4 decompression has the same 27,478,624 exclusive instructions.
Nested function counts are not added to the feed total.

## Untraced PoC results

Each combined result uses 28 ordinary fixed-key samples. Restart remains
separate. p95 uses nearest rank: sample 27 of 28. Each stable result uses the
existing median of four eight-cycle runs. Units are milliseconds.

| Pass | Combined median / p95 / maximum, before | Combined median / p95 / maximum, after | Stable median, before / after |
| --- | --- | --- | --- |
| 1 | 4.396 / 7.266 / 7.318 | 4.517 / 7.143 / 7.189 | 25.530 / 26.194 |
| 2 | 4.811 / 7.392 / 7.489 | 4.990 / 6.788 / 7.090 | 26.339 / 26.502 |

Both candidate combined medians and both stable medians increase in these
comparisons. The observed differences do not prove a sustained latency change.
All eight existing summaries pass. Each complete report matches its paired
report after timing fields and the source label are excluded. Cursors,
revisions, decoded work, compaction, historical replay, rollback, reopen, and
continuation checks remain unchanged.

The recorded targets remain 4.370082 ms median and 8.717326 ms maximum per
ordinary combined increment, and 26.985 ms median per stable eight-cycle run.
Both candidate combined medians exceed their target. Complete performance
qualification remains **Not done**.

## Writer diagnostic

A separate diagnostic uses the accepted buffered-checksum binary. Its
220 native `write_batch` calls collect 65,363,520 instructions. The two LZ4
compression functions account for 47,941,496 exclusive instructions.
The existing 8 KiB writer buffer already combines Item writes.

A separate syscall trace covers 16 journal files: 544 writes, 352 `fsync`
calls, and 568 file-position calls. It includes 56 writes of at least 16 KiB.
These counts cover the full combined driver. The trace has no syscall
durations and cannot explain an ordinary-cycle latency maximum. No
transaction-sized writer buffer or writer source change is added.

The first trace failed at `PTRACE_TRACEME` before the driver ran. Automatic
review approved the same trace with sandbox escalation. The archive retains
both attempts and the exact successful command. The successful command record
was written after completion; it claims no start or finish time.

## Verification and reproduction

Fjall passes 127 CDC library cases and 86 cases without CDC. One existing case
is ignored in each run. The new header case checks every truncated prefix,
the existing error wrappers, all decoded fields, and complete consumption.
The new uncompressed header case and existing LZ4 checksum fixture together
check both codecs. The LZ4 fixture checks unequal decoded and stored lengths.
Production without default features, library clippy,
formatting, and the release PoC build pass. Existing warnings remain. Full
workspace CI was not run during iteration, as the user requires.

- [Verification, percentiles, work equality, and archive identity](verification.json).
- [All raw reports, summaries, logs, and profiles](raw-evidence.tar.gz).
- [Native gate commands](gates.json) and [runner](gates.py).
- [Unchanged eight-call comparison sequence](compare.py).
- [Before](profile-before.py) and [after](profile-candidate.py) feed commands.
- [Feed counter verifier](analyze-cdc.py).
- [Writer commands](profile-writer.py) and [counter verifier](analyze-writer.py).
- [Profiler identity](tool.json), [host and compiler](environment.json), and [release override](release-override.toml).

All 103 archive members were compared with their original files. All 14
summaries reproduce through the unchanged summary functions. The archive
includes the prior control and parser feed profiles as diagnostic context.
Only the buffered-checksum and header profiles isolate this edit.
Frozen executables remain under `output/storage-engine-baseline-20261108`;
their hashes are in the binary manifest. Scripts run from the repository root.
Profile scripts require the recorded Valgrind installation under
`/tmp/araphor-callgrind`. Move existing profile files before rerunning those
scripts. The comparison script overwrites local reports; the archive preserves
the original measurements. The writer script records the original failed
trace; the successful retry command is in the archive.

The later [timestamped sync and wait diagnostic](waits.md) matches all saved
cursors to their exact journal commits. Its traced timings remain separate
from the untraced results above.
