# Native read comparisons

These reports retain every observation from three frozen comparisons.
All existing combined and stable assertions pass. Complete performance
qualification is **Not done**.

## Source and binaries

| Comparison | Before or control | After or candidate |
| --- | --- | --- |
| `guard` | Fjall `843f04b`, `lsm-tree` `b555031f`; [manifest](../scan-comparison/single-scan.json) | Fjall `b766e3b`, `lsm-tree` `b9f6cfda`; [manifest](standard-guard.json) |
| `retirement` | Original flat PoC control; [manifest](../control.json) | Fjall `305b566`, `lsm-tree` `b9f6cfda`; [manifest](retirement.json) |
| `point` | The same retirement binary | Fjall `66d821e`, `lsm-tree` `b9f6cfda`; [manifest](point-read.json) |

Each manifest records full source IDs and a SHA-256 binary identity. The
independent frozen binaries remain in `output/storage-engine-baseline-20261108/`:
`control`, `versioned-single-scan`, `versioned-standard-guard`,
`versioned-retirement`, and `versioned-point-read`. Dependency locks remain
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

One point-after combined pass reaches the recorded target. The other combined
pass and both stable passes exceed their median targets. These observations
do not establish complete performance qualification. Do not select one pass
and discard another pass. Component medians are nested and are not additive.

Versioned candidates pass the retained-history comparisons after writes,
compaction, and reopen. Fixed-key controls retain their original unsupported
requests. Current summaries preserve those control results. No workload,
execution order, durability setting, assertion, or primary timing boundary
changed for these comparisons. The one-batch feed changes native read diagnostic
boundaries as documented in the parent plan.

## Reproduction

Build each source state with the existing release configuration and locks.
The recorded command uses the existing cached DuckDB build; it changes no
DuckDB implementation or settings:

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
process ran concurrently with these measurement calls. The reports use the
same host, release settings, and `SyncAll` durability.

The PoC supplies prepared Arrow and synthetic source-frontier metadata.
It does not measure production DataFusion input or notification delivery.
Profiler attempts are separate diagnostics and supply no acceptance timing.
