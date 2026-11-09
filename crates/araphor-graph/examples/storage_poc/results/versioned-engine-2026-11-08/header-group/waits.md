# Journal sync and wait diagnostic

The frozen `versioned-header-group` executable runs the unchanged combined
PoC under `strace`. The command adds timestamps, syscall durations, and
`futex` to the earlier trace. Payloads remain omitted. All traced timing
fields are excluded from performance acceptance. The reviewer and implementer
agreed on the diagnostic before it ran. No source or benchmark changes occur.

The parser reconstructs 8,051 completed calls, including resumed calls.
It separates the main thread from workers. Eight journal directories occur
in the existing sequential run order without interleaved main-thread writes.
Each candidate consists of writes, their following sync, and the first
following file-position read on the same descriptor and journal path.
The parser finds 220 candidates. All 128 saved source and output cursors
match exactly one candidate by directory, journal ID, and end offset.
Repeated maintenance syncs without new writes do not create candidates.

Each result below uses 28 ordinary fixed-key samples. Restart remains
separate. p95 uses nearest rank. Units are milliseconds.

| Journal syscall | Median | p95 | Maximum |
| --- | ---: | ---: | ---: |
| Source `fsync` | 0.567 | 0.595 | 2.718 |
| Output `fsync` | 0.666 | 0.737 | 1.692 |
| Source writes, total per commit | 0.022 | 0.025 | 0.027 |
| Output writes, total per commit | 0.097 | 0.242 | 0.242 |

The largest source sync occurs at round 2, revision 87. Its traced source
commit takes 3.222444 ms. The largest output sync occurs at round 2,
revision 46. Its traced output commit takes 2.780972 ms. The source and output
each have one journal sync per matched commit. No duplicate commit sync is
found. These observations do not establish the cause of the earlier
13.984 ms untraced maximum.

Across the complete driver, the main thread makes 352 journal `fsync` calls.
Their median/p95/maximum values are 0.569/0.709/2.718 ms. Its 541 `futex` calls
include 154 waits and 387 wakes. The combined median/p95/maximum values are
0.018/0.654/1.041 ms; these are all syscall durations, not wait durations.
These totals include setup and maintenance. A `futex` call alone does not identify a channel or
lock. Worker wait intervals overlap other work and each other; their sums
are not elapsed execution time.

Syscall elapsed time includes tracing and scheduling. It is not pure device
time. The existing `output_sync_s` timer covers the complete native commit,
including encoding, memory writes, publication, and transaction cleanup.
It must not be described as an isolated sync duration. This diagnostic does
not establish a safe sync removal or another storage change. Complete
performance qualification remains **Not done**.

The independent reviewer reproduced all candidates, matched records,
distributions, and the unchanged complete-driver summary.

- [Exact trace runner](profile-waits.py) and [cursor verifier](analyze-waits.py).
- [Six raw files](wait-evidence.tar.gz): command, log, report, summary, trace, and analysis.
- [Archive identity and byte verification](wait-verification.json).
- [Frozen binary identity](binary.json).

Run scripts from the repository root. The trace requires the approved ptrace
access. Move existing `wait-current-*` files before rerunning the runner.
The parser requires the trace and report under `/tmp/araphor-callgrind`.
No full workspace CI runs for this diagnostic.
