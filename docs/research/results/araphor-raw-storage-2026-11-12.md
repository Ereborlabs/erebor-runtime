# Raw segments against versioned Fjall

Date: 2026-11-12. Result: **Done for the matched raw-storage pilot**. The user
approved benchmark development and execution. Production storage replacement,
natural sustained compaction, and complete retention/recovery parity are not qualified.

The final release binary ran 16 independent processes. Each dataset has four
pairs in AB, BA, AB, BA order. Each durable append contains 256 records. The
262,144-record input has exactly 37,445,318 original framed bytes for both
backends. Two earlier 512-record smoke runs checked the executable. An initial
16-run pilot was followed by the final matrix after an unused import was removed.
The table and archived samples below describe only the final binary and matrix.

## Measured result

| Records | Backend | Write records/s | Append median ms | Append p95 ms | Append p99 ms | Append max ms | Paged read records/s | Point read p95 ms | Reopen ms | Allocated MiB |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 16,384 | segments | 211,670 | 1.200 | 1.290 | 1.387 | 2.296 | 6,798,277 | 0.025 | 3.320 | 2.24 |
| 16,384 | fjall | 382,428 | 0.661 | 0.733 | 0.786 | 0.903 | 5,605,713 | 0.025 | 3.005 | 3.33 |
| 262,144 | segments | 210,646 | 1.202 | 1.264 | 1.327 | 6.622 | 5,572,239 | 0.037 | 55.990 | 36.40 |
| 262,144 | fjall | 373,741 | 0.674 | 0.737 | 0.792 | 3.757 | 4,920,938 | 0.032 | 23.241 | 52.96 |

Append times are per durable 256-record batch. Throughput, reopen time, and
allocated bytes are medians of four process results. Append and point-read
percentiles pool samples within one backend and dataset size: 256 append
samples for the small dataset and 4,096 for the large dataset. Quantiles use
the existing raw harness convention: sorted indexes `n/2`, `n*95/100`, and
`n*99/100`. Paged read rates include exact-byte verification and use the read
after store reopen. OS page caches were not dropped.

At the large size, Fjall has 1.77-fold higher median write throughput. Each
of the four large pairs has a higher Fjall write rate. Segments have
1.13-fold higher paged-read throughput. These results do not isolate which
implementation detail causes either difference. They are not a notification
latency result or a 100-fold improvement claim.

## What ran

The [fixture](../../../crates/araphor-data/src/analysis/raw_benchmark.rs) uses
production `RawJournal::prepare`, `prepare_append`, and `append` for segments.
The candidate uses the versioned Fjall fork. It stores the same canonical
`RawCommit` frame plus entry-index metadata and the source receipt in one
`SyncAll` branch transaction. Both maintain the same in-memory source/range
index. Candidate recovery rebuilds that index from persisted entry metadata.
Application keys use source identity and accepted source cursor, not revision.

The [release runner](../../../crates/araphor-data/examples/raw_storage_bench.rs)
checks every returned original frame and logical cursor/ordinal. The saved
cuts are written and synced outside append timing. The checks read an earlier
cut after later appends, native flush/major compaction, and owner close/reopen.
Original-log replay checks bytes, order, and logical positions. After reopen,
another batch is appended and replay continues from the saved end position.
The experiment does not simulate process termination or power loss.

The source is behind the existing `test-fixtures` feature. It does not change
production storage selection, the table API, collector registration, or the
ignored incident test. The user must approve production changes separately.

## Maintenance and resource cost

Neither dataset records a background compaction during the maintenance step.
The runner explicitly flushes and requests major compaction. The worker counter
does not count the synchronous major
compaction API. The archive records both maintenance times separately from
append latency. This is not a sustained natural-compaction workload.

- `segments`: median process user/system CPU 0.370/0.285 s; median peak RSS 104.31 MiB.
  Median seal time: 0.567 ms.
- `fjall`: median process user/system CPU 0.485/0.245 s; median peak RSS 157.52 MiB.
  Median flush/major-compaction time: 65.397/50.584 ms.

Allocated space is measured after this maintenance. All native history and
original journals remain retained for the history/replay probes. Physical
reclamation after consumer progress or witness expiry was not measured.

## Conditions and limits

- Linux 6.8.0-147-generic, AMD Ryzen 9 5900HX, ext4 on `/dev/nvme0n1p7`.
  Full CPU, mount, device, compiler, and engine identities are in the record.
- Fresh store and process per run; same host/device; backend order alternates.
  Setup writes are synchronized before timed appends. Other host activity is
  not controlled. Global `syncfs` sensitivity remains part of the segment path.
- Segments synchronize the filesystem. Fjall synchronizes its journal file.
  Buffered inserts or reduced durability are not used.
- Segment reopen checks all retained payload frames. Candidate reopen reads
  native index metadata; payload validation occurs when frames are read.
  Reopen times therefore have different eager validation work.
- Candidate preparation calls the existing segment encoder without active
  segment state and prepares an unused identity header for each batch.
  Preparation and commit samples are separate; do not attribute this small
  adapter difference to Fjall storage performance.
- One source, contiguous disjoint appends, and original batch-shaped values.
  No overlapping retry, gap-fill, expiry, witness, authorization, complete Data
  owner, DataFusion execution, or subscription wake-latency parity is claimed.
  No full CI or ignored incident execution was run.

## Reproduce and inspect

```sh
rtk proxy cargo build --offline --release --jobs 1 -p araphor-data \
  --features test-fixtures --example raw_storage_bench
rtk proxy python3 -u scripts/benchmark_raw_storage.py output/raw-storage-rerun
```

- [Summary, environment, hashes, and pair ratios](araphor-raw-storage-2026-11-12.json)
- [All final samples and process reports](araphor-raw-storage-2026-11-12.samples.json.gz)
- [Matched-process driver](../../../scripts/benchmark_raw_storage.py)
- Local build logs, initial pilot, smoke reports, and final reports:
  `output/araphor-raw-storage-20261112`.

```sh
rtk proxy python3 -c "import gzip,json; p='docs/research/results/araphor-raw-storage-2026-11-12.samples.json.gz'; print(json.load(gzip.open(p))['summary'])"
```
