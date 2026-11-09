# Native point reads and journal compression

`lsm-tree` `29549fd7` borrows native index blocks for point reads. Full,
volatile, and two-level indexes keep their sequence-aware search, cache,
materialization, and error behavior. Lazy range iterators keep their owned
index state. The point path no longer creates an owned index iterator.
The [source patch](borrowed-point.patch) starts at `4aeaf8d4`.

Fjall `42be11f` compresses native journal items directly into the writer's
existing reusable byte buffer. The codec, field order, lengths, compression
threshold, and resulting bytes remain. This removes the temporary compressed
vector, its shrink operation, and the copy into the writer buffer.
The generic entry encoder keeps its `Write` interface. Its Item case creates
a local byte vector; production item writes use the writer buffer directly.
The buffer can retain capacity for the largest uncompressed compression bound
until journal rotation. This change can increase retained buffer memory for
highly compressible values. The [source patch](lifecycle-compression.patch)
starts at `8cb06c8` and also contains the lifecycle proof below.

Fjall `f2034d0` extends the existing combined history/CDC lifecycle case.
The case stages actual output and its consumed cursor, rolls back, and checks
that head, journal, output, and progress did not change. The case then commits
the same output and progress. Historical reads also check the inherited parent
value before child creation after both reopen stages. No engine API changes.

The [point binary](borrowed-point-binary.json) and
[compression binary](direct-compression-binary.json) manifests identify exact
source commits and executable hashes. The [verification record](verification.json)
confirms all four frozen executable hashes and reproduces all 24 existing
summaries. Native default and LZ4 library suites pass 241 and 244 cases.
Three read-view and three retained-history cases pass in each configuration.
The final Fjall suites pass 125 CDC cases and 84 cases without CDC.
Existing ignored cases and warnings remain explicit in the logs.
The production check without default features, library clippy, and formatting
pass. Full workspace CI was not run during iteration.

## Unchanged PoC measurements

Units are milliseconds. Each value comes from its retained summary.
Each combined pass has 28 ordinary fixed-key cycles. Restart and maintenance
remain separate. Each stable value is the existing median of four eight-cycle
runs. All existing correctness assertions pass.

| Comparison | State | Combined median 0 | Combined max 0 | Combined median 1 | Combined max 1 | Stable median 0 | Stable median 1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Point ownership | Before | 6.001 | 10.462 | 5.646 | 12.117 | 36.000 | 36.578 |
| Point ownership | After | 5.325 | 10.109 | 5.281 | 9.801 | 35.620 | 37.036 |
| Compression | Before | 4.622 | 8.578 | 4.767 | 7.834 | 27.765 | 27.233 |
| Compression | After | 4.827 | 8.595 | 4.476 | 7.149 | 27.070 | 27.504 |
| Accumulated | Original control | 4.333 | 8.232 | 4.434 | 7.584 | 25.570 | 24.729 |
| Accumulated | Current candidate | 4.836 | 7.039 | 4.551 | 7.869 | 26.240 | 25.748 |

The point comparison uses `versioned-reader-position` before and
`versioned-borrowed-point` after. The compression comparison uses
`versioned-borrowed-point` before and `versioned-direct-compression` after.
The accumulated comparison uses the original frozen `control` before and
`versioned-direct-compression` after. No task build or test ran during these
untraced measurement calls. The host observation was taken after the point
comparison; it does not establish a cause for timing differences.
Results from separate comparison groups do not isolate a source change.
The compression and stable measurements remain mixed. No overall gain is proved.

The [ordinary percentiles](cycle-percentiles.json) include the original
recorded PoC and every combined report in this directory. Nearest-rank p95
selects sample 27 of each sorted 28-sample set. These extra statistics do not
change the existing summary calculations or acceptance criteria.

| Fixed-key ordinary cycles | Median | p95 | Maximum |
| --- | ---: | ---: | ---: |
| Original recorded PoC | 4.370 | 8.600 | 8.717 |
| Current candidate, pass 0 | 4.836 | 6.969 | 7.039 |
| Current candidate, pass 1 | 4.551 | 7.416 | 7.869 |

The current maxima are lower than the original recorded maximum. Both current
medians remain higher. The cause of earlier higher maxima is not established.
These small sample sets do not prove a sustained latency bound.

The target remains 4.370 ms median and 8.717 ms maximum for an ordinary combined
cycle, and 26.985 ms median for eight stable cycles. Both current combined
maxima and stable medians reach those targets. Both combined medians exceed
their target. Complete performance qualification remains **Not done**.

In the accumulated comparison, current Graph-read medians are 0.881 and
0.849 ms, versus 0.724 and 0.637 ms for the original control. Current result-read
medians are 0.463 and 0.455 ms, versus 0.365 and 0.357 ms. Output-CDC read
medians are 0.308 and 0.317 ms, versus 0.555 and 0.496 ms. These nested intervals
and medians are not additive. A cause for the extra read cost is not proved.
Both records layouts use the existing zero data-block hash ratio. No hash
setting changed. Retained versions do not disable an active hash fast path in
this PoC.

Versioned candidates pass exact historical checks after writes, compaction,
and reopen. The original control keeps its unsupported historical requests.
Workloads, orders, durability, assertions, and timing boundaries remain.
Prepared Arrow and synthetic source metadata remain the existing PoC limits.
The PoC does not measure production notification latency.

## Reproduction

Use the recorded source commits, source labels, and dependency locks in the
parent directory. Apply the retained source patches to their stated base
commits when the commits are unavailable. Use the existing release command
and [release override](../native-read-comparison/release-override.toml).
The override uses the cached DuckDB build; it changes no DuckDB implementation
or setting. Copy each executable to its distinct manifest path before the
next build.

[compare-index.py](compare-index.py),
[compare-compression.py](compare-compression.py), and
[compare-current.py](compare-current.py) retain the exact calls. Run each
script from the repository root with its frozen executables present.
Each script runs the unchanged drivers and existing summary checks sequentially.
Pass 0 runs before-combined, after-combined, after-stable, then before-stable.
Pass 1 runs after-combined, before-combined, before-stable, then after-stable.
