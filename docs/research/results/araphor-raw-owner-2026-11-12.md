# Raw segment and Fjall transaction comparison

This benchmark includes the production segment append and its later Fjall
metadata commit. It compares that path with an all-Fjall candidate that uses
source/cursor references. Production storage does not change.

## Intended end state

Measure both durable stages with the same input and result records. Preserve
the exact event bytes, source cursors, saved references, retained reads, and
continued log reads after reopen. Timing has no pass/fail threshold.

Result: **Done** for this finite comparison. Production replacement and complete
recovery, retention, processor, and package qualification are **Not done**.

## Measured results

Each write cycle has 256 events. The cycle includes event acceptance, input-cut
capture, input-reference resolution, and a later durable result/progress commit.
Four alternating pairs run at each retained count. All 16 process runs pass.
Rates are medians of four process rates. Latency percentiles pool the individual
cycle samples by backend and count. The larger condition has 4,096 cycle samples
per backend. The smaller condition has 256.

| Events | Storage | Cycle events/s | Cycle median ms | p95 ms | p99 ms | Maximum ms | Reopened read events/s |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16,384 | Segments + Fjall | 131,743 | 1.875 | 2.127 | 3.420 | 4.515 | 5,232,462 |
| 16,384 | All Fjall | 222,102 | 1.072 | 1.418 | 1.560 | 2.660 | 4,340,945 |
| 262,144 | Segments + Fjall | 134,385 | 1.878 | 2.018 | 3.006 | 7.395 | 4,176,305 |
| 262,144 | All Fjall | 222,738 | 1.061 | 1.391 | 1.502 | 6.757 | 3,932,056 |

At 262,144 events, the all-Fjall write-cycle rate is 1.657 times the hybrid rate.
The four matched rate ratios are 1.670, 1.598, 1.653, and 1.661. All four pairs
show higher write throughput. Reopened paged reads are about 6% slower in this
candidate. Read rates include exact-byte verification.

### Stage breakdown

The later stage resolves and validates the current input page. That stage
also serializes the result/reference/progress record, checks the previous
consumed cursor, and commits the transaction. It is not a measurement of
`SyncAll` alone. The result body and record fields are the same in both
conditions. The hybrid transaction also executes production `stage_raw` and
commits its raw metadata anchors.

| Events | Storage | Accept median ms | Accept p95 ms | Result/reference/progress median ms | Result/reference/progress p95 ms |
| ---: | --- | ---: | ---: | ---: | ---: |
| 16,384 | Segments + Fjall | 1.199 | 1.314 | 0.659 | 0.947 |
| 16,384 | All Fjall | 0.689 | 0.761 | 0.344 | 0.662 |
| 262,144 | Segments + Fjall | 1.202 | 1.285 | 0.659 | 0.743 |
| 262,144 | All Fjall | 0.688 | 0.754 | 0.336 | 0.650 |

Median input-cut capture at 262,144 events is 0.00524 ms for hybrid and
0.00489 ms for all Fjall. The cycle distribution is measured directly. It is
not a sum of the separate stage percentiles.

### Restart, log reads, and space

These are medians of four process values. Replay after reopen starts from the
saved middle result and reads the remaining 131,072 events from original logs.
The continued read starts from the saved final result and reads one new batch.

| Measurement at 262,144 events | Segments + Fjall | All Fjall |
| --- | ---: | ---: |
| Owner reopen | 78.215 ms | 28.611 ms |
| Replay 131,072 events after reopen | 17.342 ms | 20.750 ms |
| Continue with 256 new events | 0.0637 ms | 0.0737 ms |
| Allocated space after maintenance | 37.94 MiB | 53.69 MiB |
| Apparent file lengths after maintenance | 100.98 MiB | 109.04 MiB |
| Peak process RSS | 112.50 MiB | 160.14 MiB |
| Process user CPU time | 0.485 s | 0.560 s |
| Process system CPU time | 0.375 s | 0.295 s |
| Timed write cycles | 1.951 s | 1.177 s |

RSS means resident set size. CPU and RSS cover the full process, including
fixture construction, reads, maintenance, reopen, and verification. They do not
isolate storage-owner CPU or memory. The input payload has 37,445,318 bytes.

The hybrid checkpoint takes a median 15.004 ms. That checkpoint includes its
production native flush and journal collection. A subsequent explicit flush
takes 0.102 ms; explicit major compaction takes 9.842 ms. The candidate has no
external segment checkpoint. Its explicit native flush takes 70.284 ms and its
major compaction takes 62.654 ms. These times are outside the foreground cycle
measurement. Background worker compaction counters remain zero during this
maintenance interval. The explicit major-compaction call is separate from those
counters. This finite run does not qualify sustained natural compaction.

## Source review flow

Each process selects one backend and writes to one fresh store. The hybrid
append and candidate append transitions below are alternatives.

[The shared fixture](../../../crates/araphor-data/examples/raw_storage/common.rs)
constructs the same prepared events as the earlier raw-storage pilot.

[`raw_owner_bench`](../../../crates/araphor-data/examples/raw_owner_bench.rs) submits one prepared batch
  -> [`Store::append`](../../../crates/araphor-data/src/analysis/native/benchmark.rs) selects the benchmark condition.
  -> [`NativeStore::accept_validated_batch`](../../../crates/araphor-data/src/analysis/native/source/raw.rs) appends and synchronizes the hybrid raw batch.
  -> [`Candidate::append`](../../../crates/araphor-data/src/analysis/native/benchmark/candidate.rs) commits the native payload, receipt, epoch binding, and input relation positions.
  -> [`Store::cut`](../../../crates/araphor-data/src/analysis/native/benchmark.rs) captures the accepted input boundary.
  -> [`Store::consume`](../../../crates/araphor-data/src/analysis/native/benchmark.rs) resolves the current source/cursor input and commits the common result/progress record.
  -> [`DataWrite::commit_locked`](../../../crates/araphor-data/src/analysis/native/mod.rs) also stages the pending hybrid receipts and segment anchors.

[`Store::maintain`](../../../crates/araphor-data/src/analysis/native/benchmark.rs) performs explicit maintenance
  -> [`NativeStore::checkpoint`](../../../crates/araphor-data/src/analysis/native/backup/mod.rs) seals hybrid segments and applies production native journal collection.
  -> [`Store::maintain`](../../../crates/araphor-data/src/analysis/native/benchmark.rs) flushes and compacts each native database.
  -> [`Store::open`](../../../crates/araphor-data/src/analysis/native/benchmark.rs) reopens the owner after its handles are dropped.
  -> [`Store::saved`](../../../crates/araphor-data/src/analysis/native/benchmark.rs) reads the committed result and resolves its saved source/cursor reference.
  -> [`Store::replay`](../../../crates/araphor-data/src/analysis/native/benchmark.rs) reads original raw commits or the native journal after the saved cut.
  -> [`raw_owner_bench`](../../../crates/araphor-data/examples/raw_owner_bench.rs) appends another batch and checks continued output.

The hybrid condition calls the production owner. Only its replay probe reads
the existing raw revision index and original segment frames directly. The
candidate is a benchmark owner. It does not create raw segment files, segment
headers, offsets, allocator records, `RawEntry` records, or a memory range index.
Its payload key is source plus first accepted cursor. Native engine revisions
are not encoded into application keys. Native predecessor/range reads locate
batch values. Each backend uses the existing RawCommit validation and the same
original framed event bytes.

Both conditions acknowledge durable input before the later durable result.
Neither condition combines input and result progress in one transaction.
The result record has the same fields and body in both conditions. Its physical
native revision and journal cursor can differ. Consumed progress checks the
previous cursor in the same transaction that writes the result.

## Conditions and limits

- The shared release binary contains both benchmark conditions. Each measured
  process uses a fresh temporary store. The order is AB, BA, AB, BA per count.
- The host uses an AMD Ryzen 9 5900HX, Linux 6.8.0-147, ext4, and
  `/dev/nvme0n1p7`. Rust is 1.97.1. The filesystem reports 99% used and
  6.6 GiB free before the runs. No measured cause is assigned to that condition.
  No concurrent build or benchmark runs during measurement.
- Both native databases use the local versioned forks and durable `SyncAll`
  commits. The hybrid event append retains its production `syncfs` boundary.
  A setup `syncfs` runs outside the timed loop.
- The OS page cache is retained. Owner reopen occurs in the same process with
  a new native engine cache. Hybrid reopen validates retained segment payloads;
  the candidate validates event frames when it reads them. The reopen times
  therefore include different integrity work.
- Candidate native history and original event journals remain retained. Hybrid
  uses production checkpoint and journal collection. Its original event log
  remains in raw segments. Both pass the retained-cut and resume probes.
- Input is one source with disjoint contiguous batches. Overlap, retry, gaps,
  expiry, witness reclamation, branches, and killed-process or power-loss
  recovery are not qualified here. Point latency and Arrow conversion are not
  measured.
- The result/progress record belongs to the benchmark. This record does not
  qualify production `ManagedCommit`, `commit_result`, processor or witness-pin
  semantics. The benchmark does not execute Graph analysis, DataFusion, package
  code, or notifications. These times are not notification latency or a
  100-fold incident-test result. The incident test remains ignored.

## Reproduce and evidence

```sh
rtk proxy cargo build -p araphor-data --release --features test-fixtures --example raw_owner_bench --example raw_storage_bench
rtk proxy python3 scripts/benchmark_raw_storage.py --owner output/araphor-raw-owner-repeat
```

The final release build passes. Both new 512-event smoke checks pass. Both
original-pilot 512-event smoke checks also pass after extraction of the shared
fixture. All 16 measured owner runs pass the executable assertions. Focused
Rust formatting and Python syntax checks pass. Full CI is not run, as requested.
No production storage migration or existing test change is included.

The run starts from repository commit `de39c46c8` with the benchmark changes
in the working tree. The measured binary SHA-256 is
`ddec7141291cbebd5beb8c556ed61e6f2e068670b12b580c0aad10c09f723678`.
The source hashes are in the evidence. Fjall is `f745c5462`; lsm-tree is
`56d74411b`. Both fork worktrees are clean before measurement.

- [Structured summary, source identities, and resources](araphor-raw-owner-2026-11-12.json)
- [All 16 reports, individual samples, resource logs, smoke reports, and environment](araphor-raw-owner-2026-11-12.samples.json.gz)
- [Earlier raw-only pilot](araphor-raw-storage-2026-11-12.md)
- [Owning plan](../../plans/araphor-data-storage-and-collectors.md#production-path-comparison-2026-11-12)
