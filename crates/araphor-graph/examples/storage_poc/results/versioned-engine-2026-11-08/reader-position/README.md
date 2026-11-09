# Native journal position accounting

Fjall `8cb06c8` replaces the native journal reader's per-entry file-position
query with `BufReader<Take<File>>`. The remaining native read limit counts
bytes read from the file. Subtract unread buffered bytes to obtain the exact
decoded position. The original decoder, checksum, cursor format, captured end,
and tail recovery remain. No extra change log or input archive is added.

The [binary manifest](binary.json) records source commits and binary SHA-256.
`lsm-tree` remains at `4aeaf8d4`. The
[verification record](verification.json) covers 124 CDC library cases, 83 cases
without CDC, the production check without default features, library clippy,
and formatting. One existing case is ignored in each library run. Clippy
reports existing warnings. Full workspace CI was not run during iteration.

## Unchanged PoC measurements

Each row comes from its retained summary. Units are milliseconds. The first
comparison uses the preceding `versioned-direct-scan` binary as its before
state. All existing assertions pass.

| State | Combined median 0 | Combined max 0 | Combined median 1 | Combined max 1 | Stable median 0 | Stable median 1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Before, 2.8 GB free | 5.168 | 8.087 | 5.051 | 10.166 | 28.946 | 28.654 |
| Candidate, 2.8 GB free | 4.801 | 8.909 | 4.964 | 9.407 | 30.726 | 28.991 |
| Original control, after cleanup | 4.246 | 9.682 | 4.278 | 8.842 | 26.131 | 26.423 |
| Candidate, after cleanup | 4.571 | 7.231 | 4.790 | 7.367 | 26.789 | 28.352 |

Before cleanup, candidate output-CDC read medians are 0.340 and 0.336 ms,
versus 0.501 and 0.487 ms before the change. Component intervals are nested;
their medians are not additive. The stable primary interval does not include
CDC decoding, and these results establish no stable-primary gain.

The host had 2.8 GB free. No Cargo, rustc, or linker process was active when
the task removed inactive `target/debug` build artifacts under the user's
permission. Available space then increased to 134 GB. The separate
`space-reader-*` comparison uses the frozen original control and the same
candidate. Do not attribute differences across these disk states to code.
Both groups retain every observation, including the slower candidate results.

The target remains 4.370 ms median and 8.717 ms maximum for the ordinary
combined cycle, and 26.985 ms median for eight stable cycles. After cleanup,
both combined maxima pass, but both combined medians exceed the target.
Only the first stable pass reaches its target. Complete performance
qualification is **Not done**.

The [ordinary-cycle percentiles](cycle-percentiles.json) retain each combined
report's minimum, median, nearest-rank p95, and maximum. Each layout contributes
28 ordinary cycles; restart cycles remain excluded. These extra statistics do
not change the existing summaries or acceptance calculations.

Versioned candidates pass historical checks after writes, compaction, and
reopen. The original control retains its unsupported historical requests.
Fixtures, operation counts, execution order, durability, assertions, timing
boundaries, and summary calculations remain unchanged. Prepared Arrow and
synthetic input metadata remain the existing PoC limits; this is not a
production notification measurement.

## Separate diagnostics

The two `*-strace.json` reports execute the same complete combined driver.
The corresponding logs record 27,710 file-position syscalls before the change
and 3,382 afterward. These counts cover both layouts and all 64 package
cycles. All traced timing values are excluded from acceptance.

The preceding `versioned-direct-scan` binary also completed the unchanged
combined workload under GDB with 643 main-thread stack samples. Its source and
binary identity are in the [earlier manifest](../native-read-comparison/direct-scan.json).
The interval is 1 to 3 ms, with seed 1937. The script and raw
commands are retained in [`capture-combined.py`](capture-combined.py) and
[`gdb-combined-stacks.jsonl`](gdb-combined-stacks.jsonl). GDB requires the same
approved own-child tracing outside the ptrace-blocked sandbox used by the
[earlier diagnostic](../gdb-diagnostic/README.md). No system setting changed.
All debugger timing values are excluded from acceptance.

Review identifies ten definite candidate primary captures, eight flat-control
captures, and 48 primary captures with no engine identity. Fourteen rollback
captures remain separate despite misleading inner symbol aliases. Twelve
definite candidate output-commit samples show six fsync positions, three LZ4
compression positions, and one each in Start encoding, memtable insertion,
and buffered write. These are execution positions, not CPU percentages.
CDC decoding runs in the Walker thread; this diagnostic does not sample it.

## Reproduction

Use the source commits and label in `binary.json`, the dependency locks in the
parent directory, and the existing release command with the retained
[`release-override.toml`](../native-read-comparison/release-override.toml).
That override uses the existing cached DuckDB build without changing its
implementation or settings. Restore that cache at the recorded path.
Copy each executable to its distinct manifest path before the next build.

[`compare.py`](compare.py) records the first comparison's exact binary calls;
[`compare-after-cleanup.py`](compare-after-cleanup.py) records the second.
Both scripts run the unchanged driver sequentially and use the existing
`summarize_cdc.py` and `summarize_stable.py` assertions and calculations.
The order remains before-combined, after-combined, after-stable, before-stable
for pass 0; then after-combined, before-combined, before-stable, after-stable
for pass 1. No task build or test ran during these untraced measurement calls.
