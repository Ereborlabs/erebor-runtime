# Persistent segment files and file-level sync

Source: `c78e89340`. Result: **Done** for this raw-storage PoC. All 36 measured runs and three CLI smoke runs pass. One focused test passes for all three backends. Production storage and both engine forks are unchanged.

At 262,144 events, the new segment writer reaches 345,151 events/s. The original writer reaches 198,676; Fjall reaches 333,840. The new writer is 1.737 times the original rate and 3.39% above Fjall. It has a higher rate in all six matched triples. This is a modest advantage over Fjall in this finite raw-storage comparison.

## Intended end state

Measure a simpler segment writer with the same event input and durable acceptance boundary. Keep the existing codec, raw indexes, read checks, historical cuts, reopen, and original-log continuation. Keep the production owner unchanged.

## Source review and flow

[Store::append](../../../crates/araphor-data/src/analysis/raw_benchmark.rs) receives one prepared 256-record batch
  -> The existing RawJournal prepares the validated RawCommit frame and next raw index.
  -> [Segments::append](../../../crates/araphor-data/src/analysis/raw_benchmark/segments.rs) reuses the active SegmentFile.
  -> [SegmentFile::append](../../../crates/araphor-data/src/analysis/segment_file.rs) checks the expected end and writes the frame.
  -> SegmentFile syncs the file before the new index is published.
  -> Creation also syncs the segment directory. Rotation and sealing use the existing seal_all and directory sync.
  -> The benchmark publishes the same raw index, receipt, segment state, and usage accounting.

[The executable](../../../crates/araphor-data/examples/raw_storage_bench.rs) verifies the accepted state
  -> It reads every original byte, cursor, revision, and ordinal.
  -> It saves the earlier cut, reads history after later appends, and replays original logs.
  -> It performs maintenance, drops the owner, reopens, and reads the saved cut.
  -> It appends one further batch and continues from the saved final position.

The original segment condition still reopens the file on each append and calls filesystem-wide syncfs. The new condition retains one active descriptor and calls file sync_all per batch. File checks, CRC/canonical frame validation, range-index updates, and usage accounting remain. These changes are measured together; this result does not isolate the time saved by each change.

Fjall also writes a sequential WAL before it updates memory. It uses its unchanged default compression policy. SST flush and compaction are separate maintenance costs. The Fjall PoC now uses the main branch. No production branch is renamed.

## Matched results

Each condition uses the existing 16,384 or 262,144 prepared events and 256-record batches. The large input has 37,445,318 original framed bytes in every run. The [runner](../../../scripts/benchmark_raw_storage.py) uses all six permutations of three conditions at each count. Each process has a fresh store. All samples remain; no run is excluded or replaced.

| Events | Writer | Events/s | Batch p50 ms | p95 ms | p99 ms | Maximum ms |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16,384 | Original segments | 204,384 | 1.268 | 1.354 | 1.471 | 1.990 |
| 16,384 | Persistent file + file sync | 364,395 | 0.694 | 0.764 | 0.852 | 2.333 |
| 16,384 | Fjall | 345,608 | 0.725 | 0.813 | 0.885 | 3.232 |
| 262,144 | Original segments | 198,676 | 1.287 | 1.363 | 1.495 | 6.913 |
| 262,144 | Persistent file + file sync | 345,151 | 0.724 | 0.820 | 0.921 | 6.129 |
| 262,144 | Fjall | 333,840 | 0.745 | 0.849 | 0.936 | 6.248 |

Append clocks include preparation, durable write, and index publication. Rates are medians of six whole timed append-loop rates. Percentiles pool 384 small or 6,144 large per-batch samples per condition. This raw-only benchmark does not include the later Data result/reference/progress transaction.

## Reads, maintenance, and resources at 262,144 events

| Writer | Reopened scan, million events/s | Point p50 / p95 µs | Reopen ms | Allocated MiB |
| --- | ---: | ---: | ---: | ---: |
| Original segments | 6.902 | 22.070 / 29.543 | 45.698 | 36.40 |
| Persistent file + file sync | 6.877 | 22.070 / 28.566 | 44.133 | 36.40 |
| Fjall | 6.000 | 15.016 / 26.191 | 19.972 | 52.96 |

Read scans include exact-byte verification. Point clocks include lookup, frame validation, decode, and result construction; exact-output verification follows the clock. Points follow scans. OS page caches are retained. Segment open validates all retained payloads; Fjall restores index metadata and validates payloads on reads. The reopen times contain different validation work.

| Writer | Maintenance medians, ms | User / system CPU s | Peak RSS MiB |
| --- | --- | ---: | ---: |
| Original segments | seal 0.578 | 0.310 / 0.290 | 104.56 |
| Persistent file + file sync | seal 0.562 | 0.310 / 0.255 | 104.44 |
| Fjall | flush 53.775; major compaction 42.914 | 0.435 / 0.230 | 157.48 |

Maintenance is outside foreground append timing. Background compaction counters remain zero during the explicit maintenance step. The counter does not count synchronous major compaction. CPU and RSS cover the full process. Native history and original journals remain retained. This is not a sustained natural-compaction or reclamation workload.

## Verification and limits

The focused test checks all three backends across unsealed reopen, later append, sealing, append into a new segment, partial-page historical reads, and replay. The measured large input also exceeds the existing 16 MiB segment rotation boundary. All original executable assertions remain unchanged. Release build, changed-file Rust formatting, Python syntax, three CLI smoke runs, and 36 measured runs pass. Existing library warnings remain. Full CI is not run, as requested.

The host is an AMD Ryzen 9 5900HX with Linux 6.8.0-149-generic, ext4, and /dev/nvme0n1p7. The filesystem reports 100% used with 3.6G available. Setup writes are synchronized before each timed loop. No build or other benchmark runs during measurement; other host activity is not controlled. Source, compiler, engine, binary, filesystem, and CPU identities are retained in the evidence.

This PoC has one source and disjoint contiguous batches. It does not qualify overlapping retries, gap filling, expiry, witness retention, power loss, killed-process recovery, complete Data transactions, packages, Graph, DataFusion, or notifications. It does not establish a production migration decision or an inherent storage-engine ranking.

## Reproduce and evidence

```sh
rtk proxy cargo test -p araphor-data --release --features test-fixtures --example raw_storage_bench
rtk proxy cargo build -p araphor-data --release --features test-fixtures --example raw_storage_bench
rtk proxy python3 scripts/benchmark_raw_storage.py output/araphor-segment-file-repeat --segments-file
```

[Structured results](araphor-segment-file-2026-11-13.json) and [all raw samples, logs, and provenance](araphor-segment-file-2026-11-13.samples.json.gz) preserve all runs. The frozen executable remains at output/araphor-segment-file-20261113/raw_storage_bench. The [earlier raw-only comparison](araphor-raw-storage-2026-11-12.md) and [full owner comparison](araphor-raw-owner-2026-11-12.md) retain their original measurement boundaries.
