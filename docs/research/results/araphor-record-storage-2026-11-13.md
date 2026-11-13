# Per-record and batch event storage: measured results

Source: `8e2b2482f`. All 24 process runs pass. The runner measures 32.847 seconds across the run commands and their report checks.

At 262,144 events, per-record storage makes the reopened point median 5.37 times faster. Cycle throughput decreases by 29.83%. Reopened bulk reads are 4.11 times slower. Allocated space increases from 53.48 to 128.43 MiB.

## Intended end state

Measure one stored value per event against one stored value per batch. Keep the input, transaction boundaries, correctness checks, and native engine settings equal. Keep the current production owner as a separate reference. This result does not change production storage. The two candidate layouts are proofs of concept (PoCs).

## Source review and flow

[inputs](../../../crates/araphor-data/examples/raw_storage/common.rs) prepares the existing original event frames in 256-record batches
  -> [Store::append](../../../crates/araphor-data/src/analysis/native/benchmark.rs) selects the production owner or the table PoC.
  -> [Tables::append](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) validates source, CPU, epoch, and contiguous progress.
  -> [Tables::append](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) commits payload rows, one source receipt, and the logical head in one native transaction.
  -> [Store::consume](../../../crates/araphor-data/src/analysis/native/benchmark.rs) reads the accepted input and commits a result, source/cursor reference, and consumed cut in a second transaction.

[raw_owner_bench](../../../crates/araphor-data/examples/raw_owner_bench.rs) reads current and saved input
  -> [Tables::read and Tables::point](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) use native ordered ranges, predecessor selection, or exact get.
  -> [Tables::decode](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) checks CRC32C and canonical MessagePack encoding.
  -> [Store::maintain](../../../crates/araphor-data/src/analysis/native/benchmark.rs) flushes and compacts native storage.
  -> [raw_owner_bench](../../../crates/araphor-data/examples/raw_owner_bench.rs) reopens the owner and verifies saved references and append-only cuts.
  -> [Tables::replay](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) resumes the original journal and checks each row position against the head in that committed batch.
  -> [raw_owner_bench](../../../crates/araphor-data/examples/raw_owner_bench.rs) appends another batch and verifies continued journal replay.

## Conditions

The existing inputs have 16,384 or 262,144 events. Each durable intake transaction contains 256 prepared events in every condition. Per-record storage does not add a sync per event. Both PoCs use the same separate result/reference/progress transaction.

The two PoCs use real `events`, `source_receipts`, `source_epochs`, `benchmark_state`, and `benchmark_results` keyspaces in one Fjall database. They create no branches. The required production branch name remains `main`; the unchanged production reference still opens `data`. This benchmark does not rename or migrate that branch.

| Item | Batch PoC | Record PoC |
| --- | --- | --- |
| Event key | Full source identity plus first cursor | Full source identity plus event cursor |
| Event value | Original framed bytes, frame ends, intake, CPU, and original Data revision | One original framed record, intake, CPU, and original Data revision/ordinal |
| Source receipt | One live row per source | One live row per source |
| Span and global position indexes | None | None |
| Value checks | CRC32C, canonical decoding, metadata and boundary checks | CRC32C, canonical decoding, metadata checks |
| Historical event cut | Filter immutable rows by saved logical revision | Filter immutable rows by saved logical revision |

The source identity occupies 73 bytes for this fixture. The cursor adds eight bytes. Each PoC event key is 81 bytes. The full source identity is repeated for each stored value. The test does not use a compact source ID. An unchanged epoch binding is checked but not rewritten by either PoC. Both PoCs use the same receipt and result writes.

A receipt stores the intake ACK frontier. Consumed progress stores the processor frontier. These values have different owners. Original event positions remain in the stored values; one latest position per source cannot replace those positions.

One release binary runs all conditions. Each dataset has four repetitions with these orders: production/batch/record, record/batch/production, batch/record/production, and production/record/batch. Every batch/record pair alternates its relative order. Each run has a fresh process and store. No build runs during the matrix. The OS page cache stays enabled. Reopen creates a new engine cache in the same process.

The root filesystem is NVMe/ext4. Its recorded free space is in the JSON provenance. The root checkout has pre-existing unrelated edits; all conditions use the same compiled source state. Both engine forks are unchanged and clean. Their exact commits, 148 source hashes, compiler, host, binary hash, and run orders are in the JSON record.

The engine keeps its default settings. The [journal configuration](../../../fjall/src/db_config.rs) enables LZ4 with a 4,096-byte threshold. The [journal writer](../../../fjall/src/journal/writer.rs) selects compression per value. Large batch values and short record values therefore use different encoding paths. This run does not isolate the time or space effect of compression.

## Durable write results

Acceptance includes validation, value encoding, and the first durable commit. Cycle time also includes cut capture, the input read, and the second durable result/reference/progress commit. Percentiles pool equal-size transaction samples. Throughput is the median of four process rates. Times are per 256-record transaction.

| Events | Condition | Accept p50 / p95, ms | Cycle p50 / p95, ms | Cycle events/s | Allocated MiB |
| ---: | --- | ---: | ---: | ---: | ---: |
| 16,384 | Production reference | 0.767 / 0.832 | 1.421 / 1.563 | 186,872 | 3.41 |
| 16,384 | Batch PoC | 0.719 / 0.825 | 1.114 / 1.558 | 204,154 | 3.46 |
| 16,384 | Record PoC | 1.109 / 1.282 | 1.865 / 2.093 | 137,036 | 8.02 |
| 262,144 | Production reference | 0.777 / 0.865 | 1.442 / 1.583 | 184,590 | 54.42 |
| 262,144 | Batch PoC | 0.736 / 0.815 | 1.335 / 1.494 | 201,081 | 53.48 |
| 262,144 | Record PoC | 1.066 / 1.248 | 1.792 / 2.068 | 141,093 | 128.43 |

The large per-record cycle rate is lower in all four isolated pairs. The large per-record point median is lower in all four pairs. These results are not notification latency measurements. The JSON record includes p99, maximum, and every transaction sample.

## Reads

Scan clocks include exact-byte and position verification. Each page returns 256 records. Point clocks include snapshot capture, lookup, CRC/canonical decode, and result construction. Point clocks stop before exact-output verification. The point workload is the existing raw pilot selection: one cursor per prepared batch, at `index * 256 + (index * 37) % 256 + 1`. Point results compare only the two PoCs. Production has no measured point result.

| Events | Condition | Warm scan, million events/s | After maintenance | Reopened | Reopened point p50 / p95, µs |
| ---: | --- | ---: | ---: | ---: | ---: |
| 16,384 | Production reference | 5.309 | 7.326 | 6.439 | Unmeasured |
| 16,384 | Batch PoC | 5.791 | 3.565 | 5.753 | 13.271 / 13.970 |
| 16,384 | Record PoC | 1.982 | 1.278 | 1.431 | 3.353 / 5.797 |
| 262,144 | Production reference | 7.127 | 7.110 | 5.134 | Unmeasured |
| 262,144 | Batch PoC | 8.433 | 4.300 | 5.443 | 28.149 / 36.740 |
| 262,144 | Record PoC | 1.313 | 1.317 | 1.325 | 5.238 / 8.731 |

Each point phase follows that condition's complete scan. These point results do not represent cold disk reads. The extra PoC point work is outside the scan and write clocks. Whole-process CPU and RSS include different work because the production reference omits the point phase.

## Measured space and lifecycle

Filesystem allocation is measured after checkpoint, flush, and forced major compaction. Live logical byte counts are measured separately. Production groups are prefixes inside its existing physical keyspace. PoC groups are real named keyspaces. These counts do not include historical versions, engine index/filter blocks, catalogue records, file padding, or allocator overhead. They do not measure device-write amplification.

| Large workload | Production reference | Batch PoC | Record PoC |
| --- | ---: | ---: | ---: |
| Reopen, ms | 79.113 | 19.594 | 207.207 |
| Original-log replay, ms | 16.654 | 16.190 | 67.454 |
| Resumed replay, ms | 16.773 | 17.091 | 73.012 |
| Forced checkpoint, ms | 78.944 | 0.001 | 0.002 |
| Forced flush, ms | 0.104 | 65.272 | 43.228 |
| Forced compaction, ms | 51.222 | 55.070 | 170.915 |
| Peak RSS, MiB | 136.414 | 161.422 | 241.111 |
| Process user CPU, s | 0.655 | 0.575 | 1.890 |
| Process system CPU, s | 0.265 | 0.290 | 0.540 |

All reports record zero background compactions. Forced compaction is exercised. Sustained natural compaction and power-loss recovery are not measured.

| Event entries at 262,144 events | Batch PoC | Record PoC |
| --- | ---: | ---: |
| Live event rows | 1,024 | 262,144 |
| Logical event key bytes, MiB | 0.079102 | 20.250000 |
| Logical event value bytes, MiB | 36.480963 | 40.288763 |

Each PoC has one live source receipt and one source epoch row. The record layout removes batch packing but repeats the source key and row metadata for every event. The stored keys increase from 81 KiB to 20.25 MiB. Logical event values increase from 36.481 to 40.289 MiB. These are measured logical bytes, not a full decomposition of the physical allocation increase.

The production reference has 1,024 payload rows, 1,024 span rows, and 1,024 position rows. Live span and position keys plus values total 0.251 MiB. The earlier space increase cannot be assigned to those live indexes alone from this result. There are no expiry rows in this workload.

The engine journal statistic reports file length, including preallocated space. Its large-workload medians are 64 MiB for production and batch, and 66.337 MiB for records. These lengths are not occupied filesystem blocks. Use the allocated MiB column for actual filesystem allocation. No complete allocation-by-file-category result is claimed.

## Verification and limits

The focused release command passes the existing partial-history test across production, the older candidate, and both new table layouts. It checks exact bytes and original positions, an input split at record 17, selected single records, live row counts, maintenance, and reopen. All 24 measured runs also pass saved references, original-log resume, continued input, unaligned pages, partial tails, and append-only cut checks. Changed Rust files pass formatting. The runner passes Python compilation and completes the full matrix.

The production library is compiled with the example. Existing library warnings remain. Full CI is not run, as the user requires. The synthetic incident remains ignored. No production storage, branch, engine API, or collector is changed by this benchmark.

The PoCs do not qualify native retained table history, historical receipt updates, deletion, expiry, overlapping retry, multiple-source global commit-order scans, witness retention, or subscription-wake latency. One source and contiguous immutable records define this comparison. A compact-source-ID key layout is not measured. Table and branch integration remain separate implementation work.

## Reproduce

```sh
cargo test -p araphor-data --release --features test-fixtures --example raw_owner_bench
cargo build -p araphor-data --release --features test-fixtures --example raw_owner_bench
python3 scripts/benchmark_record_storage.py output/araphor-record-storage-20261113
```

The runner stops after the declared 24 process runs. The archive contains each report, transaction/scan/point samples, process resource record, provenance, and focused verification log. A frozen binary remains at `output/araphor-record-storage-20261113/raw_owner_bench`; its hash matches the measured binary.

[Machine-readable result](araphor-record-storage-2026-11-13.json) and [raw samples](araphor-record-storage-2026-11-13.samples.json.gz) retain the evidence.
