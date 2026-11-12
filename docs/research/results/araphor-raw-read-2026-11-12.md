# Native Fjall read access investigation

This investigation compares native Fjall access paths for the existing raw
event benchmark. It keeps the original event bytes, 256-record output pages,
durable writes, history, and log-resume checks. Production storage does not
change. The earlier [owner comparison](araphor-raw-owner-2026-11-12.md) defines
the input, transaction, retention, and restart conditions.

## Intended end state

Find avoidable read work. Measure a native alternative with the same records
and validation. Keep the alternative only when the measured behavior supports
its stated purpose. Do not infer a storage-engine bottleneck from elapsed time.

Result: **Done** for two finite access-path experiments. A native continuous
scan gives a modest bulk-read gain. The independent-page implementation stays
unchanged. Production migration and a general table API remain **Not done**.

## Measured bulk-read result

Each condition runs in a fresh process and store. Both conditions use the same
release binary. The `pages` condition captures a view and starts a lookup for
each page. The `stream` condition holds one view and one native source-prefix
iterator for the complete scan. Both emit the same 256-record pages and check
every original byte, cursor, revision, and ordinal.

Four alternating pairs run at each count. All 16 runs pass. These values are
medians of four complete scan rates. Snapshot capture, validation, output
copies, and byte verification are inside both complete scan timers.

| Events | Read state | Independent pages, events/s | Native stream, events/s | Rate ratio |
| ---: | --- | ---: | ---: | ---: |
| 16,384 | Before maintenance | 8,283,471 | 8,852,366 | 1.069 |
| 16,384 | After flush and compaction | 4,296,506 | 4,387,655 | 1.021 |
| 16,384 | After reopen | 4,994,260 | 5,650,735 | 1.131 |
| 262,144 | Before maintenance | 7,527,377 | 7,876,721 | 1.046 |
| 262,144 | After flush and compaction | 3,611,731 | 3,914,550 | 1.084 |
| 262,144 | After reopen | 4,427,753 | 4,813,199 | 1.087 |

The large reopened scan improves by 8.7%. The four matched rate ratios are
1.059, 1.099, 1.094, and 1.125. All four large post-maintenance pairs also
improve, by 7.3% to 9.7%. Results before maintenance and at the smaller count
are more variable. This result does not show a large general read-speed gain.

The large reopened scan takes about 59.2 ms with independent pages and 54.5 ms
with the native stream, using the median rates above. Stream page samples are
emission intervals. The first interval includes fixed-view and iterator setup;
later intervals do not. They are not independent-request latency samples.
The evidence preserves all sample distributions, including p95 and p99.

Both modes use the same write path. Their measured write-cycle rates are
228,172 and 230,449 events/s in this matrix. No write improvement is claimed.
The driver compares Fjall modes. This result does not establish a streaming
Fjall-versus-segments result from the earlier independent-page measurements.

## Point-lookup experiment

The first experiment tried native `get` before the predecessor range lookup.
It also deferred forward-range creation until another batch was needed.
Snapshots, frame validation, and copying stayed at their original boundaries.
The 16 paired runs pass correctness checks.

At 262,144 events, reopened median rates are 4,012,860 before and 4,249,878
after the change, about 5.9% higher. One of four reopened pairs is slower.
Smaller-count and maintenance results are mixed. This evidence does not
establish a decisive gain. The point-lookup change is removed. Its patch,
source, binary identities, and samples remain in the archive.

The point experiment uses the preserved prior release binary and a changed
release binary. The changed binary also runs three new boundary probes after
all timed operations. Those probes do not change the timed read workload.
They prevent an exact comparison of complete-process CPU work between those
two binaries. The later stream experiment uses one binary for both modes and
has the same probes on both sides.

## Source review flow

[`raw_owner_bench`](../../../crates/araphor-data/examples/raw_owner_bench.rs) starts one timed scan
  -> [`Store::scan`](../../../crates/araphor-data/src/analysis/native/benchmark.rs) selects the storage owner.
  -> [`Store::scan`](../../../crates/araphor-data/src/analysis/native/benchmark.rs) captures one DataView for a hybrid scan.
  -> [`NativeStore::read_page_at`](../../../crates/araphor-data/src/analysis/native/source/raw.rs) reads each hybrid page from that captured view.
  -> [`Candidate::scan`](../../../crates/araphor-data/src/analysis/native/benchmark/candidate.rs) captures one BranchSnapshot for a Fjall scan.
  -> [`BranchSnapshot::prefix`](../../../fjall/src/versioned/read.rs) supplies one native iterator for that source.
  -> [`Candidate::decode`](../../../crates/araphor-data/src/analysis/native/benchmark/candidate.rs) validates each selected batch.
  -> [`Candidate::scan`](../../../crates/araphor-data/src/analysis/native/benchmark/candidate.rs) copies the original records into full or final partial pages.
  -> [`raw_owner_bench`](../../../crates/araphor-data/examples/raw_owner_bench.rs) checks the bytes and logical positions.

The hybrid and candidate transitions are alternative storage conditions.
The measured streaming matrix uses Fjall. Both owners pass focused correctness
checks. A captured view stays alive until the scan returns or an error exits
the scan. A later scan captures a new view. No view is reused across writes,
maintenance, or reopen.

[`stream_partial_history`](../../../crates/araphor-data/examples/raw_owner_bench.rs) writes one 256-record input as batches of 17 and 239 records
  -> The test captures the cut after the first batch.
  -> The test appends the second batch.
  -> The current stream emits one complete 256-record page.
  -> The saved-cut stream emits one partial 17-record page.
  -> The test repeats both reads after flush and compaction.
  -> The test repeats both reads after owner reopen.

The test checks bytes, source cursors, commit revisions, and ordinals on both
backends. The main executable also checks unaligned pages, final partial
independent pages, and saved-cut streams after the existing resume probes.
No timed workload, original assertion, or timeout is removed.

## Investigation facts and limits

- Independent Fjall pages create a snapshot and range iterator for each page.
  The stream removes repeated setup between pages. It uses native iteration;
  it does not create a second index, payload cache, or application revision key.
- Native range creation builds bounds and iterator/merge state. SST data reads
  are lazy. Creating an unused forward range does not by itself prove another
  file read. The [LSM range owner](../../../lsm-tree/src/range.rs) and
  [branch iterator](../../../fjall/src/versioned/scan.rs) define this behavior.
- Native materialization uses slices for stored values. The block cache holds
  uncompressed blocks. This investigation does not prove that decompression,
  disk I/O, frame decoding, or copying dominates. No engine, codec,
  compression, cache-size, durability, or storage-layout change is made.
- `perf stat -e cpu-clock -- true` fails because host perf access is disabled
  at `perf_event_paranoid=4`. No host setting is changed. There is no sampled
  CPU profile for this result.
- The filesystem is ext4 on `/dev/nvme0n1p7`, reports 99% used, and has about
  6.5 GiB free. The OS page cache is retained. Each owner reopen has a new
  native engine cache. No concurrent build or benchmark runs during measurement.
- The scan uses a fixed snapshot for the whole query. Independent page calls
  remain available. This access-path comparison does not implement DataFusion
  wiring, Graph analysis, notifications, production retention parity, or a
  general table abstraction.

## Reproduce and evidence

```sh
rtk proxy cargo build -p araphor-data --release --features test-fixtures --example raw_owner_bench
rtk proxy cargo test -p araphor-data --release --features test-fixtures --example raw_owner_bench stream_partial_history -- --exact
rtk proxy python3 scripts/benchmark_raw_reads.py target/release/examples/raw_owner_bench target/release/examples/raw_owner_bench output/araphor-stream-repeat --scan-modes pages stream
```

The focused test passes on both owners. The final release build, four
512-event mode/backend smoke checks, Rust formatting, and Python syntax checks
pass. All 32 measured process runs across the two experiments pass their
executable checks. Full CI and the ignored incident test are not run.

The investigation starts at `957475fbe`. The final stream binary SHA-256 is
`7fe9dc69dc2cc1c8ddfe6cdaccf57a1d68dd720b7c58f3e264aa40b16c42d109`.
Fjall remains `f745c5462`; lsm-tree remains `56d74411b`. Source and binary
identities for each experiment are recorded separately.

- [Structured results and identities](araphor-raw-read-2026-11-12.json)
- [All reports, samples, resource logs, measured source, point patch, and environment](araphor-raw-read-2026-11-12.samples.json.gz)
- [Owning plan](../../plans/araphor-data-storage-and-collectors.md)
