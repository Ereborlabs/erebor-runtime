# Native read comparisons

These reports retain every observation from six frozen comparisons.
All existing combined and stable assertions pass. Complete performance
qualification is **Not done**.

## Source and binaries

| Comparison | Before or control | After or candidate |
| --- | --- | --- |
| `guard` | Fjall `843f04b`, `lsm-tree` `b555031f`; [manifest](../scan-comparison/single-scan.json) | Fjall `b766e3b`, `lsm-tree` `b9f6cfda`; [manifest](standard-guard.json) |
| `retirement` | Original flat PoC control; [manifest](../control.json) | Fjall `305b566`, `lsm-tree` `b9f6cfda`; [manifest](retirement.json) |
| `point` | The same retirement binary | Fjall `66d821e`, `lsm-tree` `b9f6cfda`; [manifest](point-read.json) |
| `active` | The same point-read binary | Fjall `e2c23cb`, `lsm-tree` `4088a934`; [manifest](active-scan.json) |
| `bound` | The same original flat PoC control | Fjall `e2c23cb`, `lsm-tree` `4aeaf8d4`; [manifest](lower-bound.json) |
| `direct` | The same lower-bound binary | Fjall `3f684ab`, `lsm-tree` `4aeaf8d4`; [manifest](direct-scan.json) |

Each manifest records full source IDs and a SHA-256 binary identity. The
independent frozen binaries remain in `output/storage-engine-baseline-20261108/`:
`control`, `versioned-single-scan`, `versioned-standard-guard`,
`versioned-retirement`, `versioned-point-read`, `versioned-active-scan`,
`versioned-lower-bound`, and `versioned-direct-scan`. Dependency locks remain
in the parent result directory. The point comparison changes native staged
lookup and removes the branch point-read overlay. The guard comparison also
includes lazy exact historical cursor lookup.

The subsequent Fjall `e2c23cb` commit changes the combined functional lifecycle
test. It adds concurrent snapshot registration, floor advancement, reclamation,
and resume checks. Engine code remains the code measured at `66d821e`.

## Measurements

Each number below comes from its existing summary file. Units are milliseconds.
Passes 0 and 1 each run the complete existing driver. The source target remains
4.370 median and 8.717 maximum for the combined ordinary cycle, and 26.985 median
for the stable eight-cycle run.

| Group and side | Combined median, pass 0 | Combined max, pass 0 | Combined median, pass 1 | Combined max, pass 1 | Stable median, pass 0 | Stable median, pass 1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Guard before | 4.563 | 8.120 | 4.852 | 8.255 | 27.450 | 27.549 |
| Guard after | 4.401 | 8.152 | 4.899 | 8.608 | 27.185 | 27.443 |
| Retirement control | 4.724 | 10.187 | 4.300 | 8.149 | 26.928 | 25.979 |
| Retirement candidate | 5.106 | 9.237 | 4.786 | 8.129 | 27.707 | 28.195 |
| Point before | 4.752 | 9.196 | 4.881 | 9.358 | 28.035 | 29.239 |
| Point after | 4.350 | 7.698 | 4.813 | 8.234 | 27.885 | 28.203 |
| Active before | 5.332 | 8.400 | 4.998 | 8.476 | 28.314 | 28.352 |
| Active after | 4.701 | 8.329 | 4.897 | 8.167 | 28.256 | 28.714 |
| Bound control | 4.208 | 7.234 | 3.843 | 8.163 | 25.629 | 25.369 |
| Bound candidate | 4.328 | 7.094 | 4.771 | 8.079 | 26.155 | 28.384 |
| Direct before | 4.820 | 8.040 | 5.047 | 9.586 | 28.070 | 30.152 |
| Direct after | 4.859 | 8.411 | 4.668 | 8.318 | 28.921 | 29.287 |

One point-after combined pass reaches the recorded target. The other combined
pass and both stable passes exceed their median targets. These observations
do not establish complete performance qualification. Do not select one pass
and discard another pass. Component medians are nested and are not additive.

Bound candidate pass 0 reaches both recorded targets. Bound candidate pass 1
exceeds both median targets. The result is not yet repeatable. Complete
performance qualification remains **Not done**.

The [cycle percentiles](cycle-percentiles.json) also record the user-requested
minimum, median, p95, and maximum for the original and measured candidates.
Each report selects the same 28 ordinary cycles and excludes restart cycles.
The p95 calculation uses the nearest-rank definition in
[`summarize.py`](../../../summarize.py): sort the retained combined values and
select position `ceil(0.95 * count)`. The combined and stable summary scripts
do not emit p95. These descriptive
statistics do not change the existing summary or acceptance calculations.

Versioned candidates pass the retained-history comparisons after writes,
compaction, and reopen. Fixed-key controls retain their original unsupported
requests. Current summaries preserve those control results. No workload,
execution order, durability setting, assertion, or primary timing boundary
changed for these comparisons. The one-batch feed changes native read diagnostic
boundaries as documented in the parent plan.

## Reproduction

Build each source state with the existing release configuration and locks.
The command below is the point-read example. For another group, use its
manifest source commits and `source_label`. The command uses the existing
cached DuckDB build; it changes no DuckDB implementation or settings.
The [retained override](release-override.toml) records that local cache path.
Restore the same cached build at that path before use:

```sh
CARGO_TARGET_DIR="$PWD/target" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 \
POC_SOURCE_REVISION=51b4c9d18+point-read \
cargo build --release \
  --manifest-path crates/araphor-graph/examples/storage_poc/neon-bench/Cargo.toml \
  --config /tmp/araphor-storage-release-override.toml --offline
```

Copy the resulting binary to a distinct file before building another source
state. For each group, run sequentially in this order:

```text
before/control combined 0
after/candidate combined 0
after/candidate stable 0
before/control stable 0
after/candidate combined 1
before/control combined 1
before/control stable 1
after/candidate stable 1
```

Run the frozen binary as `BINARY REPORT.json combined` or
`BINARY REPORT.json stable`. Generate each summary with the existing
`summarize_cdc.py REPORT.json` or `summarize_stable.py REPORT.json`. Each retained
raw report has a corresponding summary and execution log. No build or test
started by this task ran concurrently with these measurement calls. The reports use the
same host, release settings, and `SyncAll` durability.

The PoC supplies prepared Arrow and synthetic source-frontier metadata.
It does not measure production DataFusion input or notification delivery.
Profiler attempts are separate diagnostics and supply no acceptance timing.
The [GDB diagnostic](../gdb-diagnostic/README.md) retains 151 paused main-thread
stacks from the unchanged stable driver. Its timings are excluded. It does not
establish the cause of the median regression.
