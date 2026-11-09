# Unapplied visibility-aware point-seek experiment

Result: **Not applied. Complete performance qualification remains Not done.**
The reviewer and implementer agree to remove the [patch](sequence-seek.patch).
The accepted source remains `lsm-tree` `aed3e47a` and Fjall `42be11f`.

The experiment uses the existing native binary search to select the restart
before a requested key and exclusive sequence cut. The existing point-read
loop selects the visible value or deletion. Hash hits, stored bytes, public
APIs, cache settings, and range scans remain. A new oracle compares key,
sequence, value type, and payload across many restart intervals. The oracle
covers both tombstone types, empty values, zero and maximum cuts, two- and
four-byte offsets, and absent, conflicted, and direct hash entries.

Complete neighbor-query instructions increase from 136,189,231 to 138,447,850,
or 1.66%. Their median increases from 4,679,004 to 4,772,707.5, or 2.00%.
Every collected revision median increases. The code section grows by 8,832
bytes. These results contradict a query CPU improvement for this workload.
The mixed wall-time results below do not justify keeping the experiment.

| State, milliseconds | Combined median 0 | p95 0 | Max 0 | Combined median 1 | p95 1 | Max 1 | Stable median 0 | Stable median 1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Accepted source | 4.763 | 7.002 | 7.175 | 4.840 | 7.326 | 7.337 | 26.098 | 26.595 |
| Unapplied experiment | 4.409 | 7.089 | 7.466 | 4.882 | 7.151 | 7.268 | 25.906 | 26.374 |

Each combined pass has 28 ordinary fixed-key cycles. Nearest-rank p95 selects
sample 27. Restart remains separate. Each stable value is the existing median
of four eight-cycle runs. All eight reports pass the unchanged summary checks.
Complete before/after reports match in every non-timing field except the
source label. Both candidate combined medians exceed the 4.370 ms target.

Native default/LZ4 library suites pass 242/245 cases, with two existing ignored
cases each. Three read-view and three retained-history cases pass in each
configuration. Fjall passes 125 CDC cases and 84 cases without CDC, with one
existing ignored case each. The production check without default features,
library clippy, and formatting pass. Existing warnings remain. Full workspace
CI was not run during iteration, as the user requires.

The [binary manifest](sequence-seek-binary.json) identifies exact sources,
patch and executable hashes, and code sizes. [compare.py](compare.py) retains
the same eight untraced calls and balanced order. No task build, test, or
profiler ran during these untraced calls. Restore the sources and commands
from the [preceding accepted comparison](../parser-inlining/README.md).
Apply this patch only to reproduce this experiment.

The [raw archive](raw-evidence.tar.gz) contains the eight reports, existing
summaries, logs, profiler command, all 79 new raw profiles, and complete
instruction analysis. Its `output/` directory contains the untraced evidence;
its `callgrind/` directory contains the diagnostic evidence. The preceding
archive contains the before profiles. Use its `analyze-cycles.py` with arguments
`inline sequence` after placing both profile sets under `/tmp/araphor-callgrind`.
The [verification record](verification.json) checks nine summaries, both
executable hashes, the patch, and every archived member against its original.

The instruction diagnostic selects the same 28 ordinary evaluations and 92
neighbor calls. Presence collects no instructions. Rollback, restart, and all
profiled timings remain excluded. The PoC does not measure production
notification latency. These small sample sets do not establish a sustained
latency bound; the cause of earlier higher maxima remains unverified.
