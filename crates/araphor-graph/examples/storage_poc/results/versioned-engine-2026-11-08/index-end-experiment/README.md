# Unapplied index-seek experiment

Result: **Not applied. Complete performance qualification remains Not done.**
The independent reviewer and implementer agree to remove this experiment.
`lsm-tree` stays at `aed3e47a`; Fjall stays at `42be11f`.

The [patch](index-end.patch) reuses the existing index search result to detect
an exhausted forward seek. It removes one repeated restart-key decode.
The original binary search, reverse seek, scanner exhaustion, and stored bytes
remain. An added single-entry case checks exclusive sequence cuts, forward
exhaustion, and the last reverse entry. All native and PoC checks pass.

The complete evidence does not establish a general improvement. Collected
query instructions decrease by 0.593%, but their median increases. Early
revision medians increase; later revision medians decrease. The code section
grows by 8,256 bytes. Combined timing medians decrease in both comparisons;
both stable timing medians increase. The timing tails remain mixed.
The decision uses these complete results and the extra code cost. It does not
assign a cause to a small wall-time difference.

## Unchanged measurements

Units are milliseconds. Each combined pass has 28 ordinary fixed-key cycles.
Restart remains separate. Each stable value is the existing median of four
eight-cycle runs. All existing summary assertions pass.

| State | Combined median 0 | p95 0 | Max 0 | Combined median 1 | p95 1 | Max 1 | Stable median 0 | Stable median 1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Retained source | 4.876 | 7.041 | 7.316 | 4.826 | 7.516 | 7.720 | 26.128 | 26.345 |
| Unapplied experiment | 4.617 | 7.393 | 8.395 | 4.672 | 6.982 | 7.128 | 26.467 | 26.878 |
| Original recorded PoC | 4.370 | 8.600 | 8.717 | | | | 26.985 | |

The [percentile record](cycle-percentiles.json) retains each minimum, median,
p95, and maximum. Nearest-rank p95 selects sample 27 of each sorted 28-sample
set. The existing summary calculations and acceptance criteria remain.
The cause of earlier higher maxima is not established. These sample sets do
not establish a sustained latency bound. Both retained-source combined
medians exceed the 4.370 ms target.

The [instruction comparison](inline-end-instructions.json) selects the same
28 ordinary fixed-key evaluations and 92 neighbor calls. Complete query
instructions decrease from 136,189,231 to 135,381,114. Their median increases
from 4,679,004 to 4,706,154. The existing diagnostic excludes rollback and
restart. Presence calls collect no instructions. All profiled timings remain
excluded from acceptance. Instructions do not measure I/O wait or whole-cycle
latency.

## Source, verification, and reproduction

The [binary manifest](index-end-binary.json) records the exact source base,
patch and executable hashes, and code sizes. Native default/LZ4 library
suites pass 242/245 cases, with two existing ignored cases each. Three native
read-view and three retained-history cases pass in each configuration. Fjall
passes 125 CDC cases and 84 cases without CDC, with one existing ignored case
each. The production check without default features, library clippy, and
formatting pass. Existing warnings remain. These logs cover the unapplied
experiment. The restored source is byte-identical to `aed3e47a`.
Full workspace CI was not run during iteration, as the user requires.

[compare.py](compare.py) retains the same eight untraced calls and balanced
execution order. It uses `versioned-inline-parser` before and
`versioned-index-end` after. Workloads, durability, cache settings, assertions,
and timing boundaries remain. No task build, test, or profiler ran during
these untraced calls. Restore the sources and build commands from the
[preceding comparison](../parser-inlining/README.md). Apply this patch only to
reproduce this experiment.

The [profiler command](end-command.json) uses the same Callgrind collection
and analysis as that preceding comparison. The [raw archive](callgrind-profiles.tar.gz)
contains every new profile. Use the preceding archive for the before profiles
and its `analyze-cycles.py` with arguments `inline end` for analysis.
The [verification record](verification.json) checks the executable and patch
hashes, all nine summaries, and each archived profile against its original.
Prepared Arrow and synthetic source metadata remain the existing PoC limits.
Production notification latency is not measured.
