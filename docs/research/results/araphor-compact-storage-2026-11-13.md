# Compact source keys: measured event storage

Source: `b9dbb2632`. All 32 process runs pass. The runner measures 57.325 seconds across the run commands and report checks.

At 262,144 events, compact per-record durable intake is 229,944 events/s. Compact batch intake is 334,037 events/s. The per-record median rate is 31.16% lower. Compact keys reduce record allocation from 128.48 to 107.12 MiB. All four repetitions remain in the statistics, including the two slow final runs below.

## Intended end state

Measure compact source IDs with the existing input, transaction size, event values, and validation. Compare both key widths and both payload granularities. These are proofs of concept (PoCs). No production or engine migration is part of this result.

## Source review and flow

[Tables::open](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) opens real keyspaces and restores a source ID from both durable mappings
  -> [Tables::append](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) validates the input and allocates a nonzero eight-byte ID for a new compact source.
  -> [Tables::append](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) commits both maps, allocator, event rows, receipt, and head in one native transaction.
  -> [Tables::append](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) publishes the cached ID after successful commit.
  -> [Store::consume](../../../crates/araphor-data/src/analysis/native/benchmark.rs) reads the input and commits its result, reference, and consumed cut in the second transaction.

[Tables::point/read/scan](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) selects source-scoped rows
  -> [Tables::rows](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) checks each value and returns original bytes and positions.
  -> [raw_owner_bench](../../../crates/araphor-data/examples/raw_owner_bench.rs) verifies partial pages, maintenance, saved cuts, and reopen.
  -> [Tables::replay](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) reads original journal items for that source and checks the same committed head.
  -> [raw_owner_bench](../../../crates/araphor-data/examples/raw_owner_bench.rs) accepts another batch and checks continued replay.

An unbound compact source has no event prefix. Its reads, points, scans, and replay return no rows. The `compact_sources_reopen` test admits two sources sequentially. It checks distinct IDs, stable original positions, source-scoped replay, and both source reads after compaction and reopen.

## Conditions

The [earlier batch/record comparison](araphor-record-storage-2026-11-13.md) remains unchanged. This matrix reruns all four variants in one release binary. Each run uses the same 16,384 or 262,144 events and 256 events per transaction. Per-record storage retains one SyncAll intake commit per prepared batch, followed by one result/reference/progress commit.

| Item | Long keys | Compact keys |
| --- | --- | --- |
| Event key | Full source identity: 73 bytes; cursor: 8 bytes | Source ID: 8 bytes; cursor: 8 bytes |
| Key length | 81 bytes | 16 bytes |
| ID registration | None | First intake commits both maps and allocator |
| Reopen | Reconstruct full source key | Resolve and validate committed ID |
| Receipt, epoch, result, and event values | Existing PoC encoding | Same encoding |

All variants create the same real keyspaces. `source_ids` maps full identity to ID. `sources` maps ID to full identity. Long-key variants leave both maps empty. Compact variants add one row in each and one allocator row. Mapping registration is inside the first measured acceptance. Full identity remains in existing source-level receipt and epoch records. Event keys contain no table-name prefix. No branch is created. The required production branch remains `main`; its migration is outside this benchmark.

The four orders per dataset are long-batch/long-record/compact-record/compact-batch; long-record/compact-batch/long-batch/compact-record; compact-batch/compact-record/long-record/long-batch; compact-record/long-batch/compact-batch/long-record. Each variant occupies each position once. Fresh processes and stores produce 32 runs. No build runs during measurement. The OS page cache stays enabled.

Native database and table settings are unchanged. Each granularity has exactly equal event value bytes across key widths. CRC32C, canonical MessagePack checks, original Data revision/ordinal, intake time, CPU, receipts, and result handling remain the same. Journal compression still applies per value at the default 4,096-byte threshold. This run does not isolate compression cost. Exact source hashes, binary hash, engine commits, host, compiler, filesystem, and orders are in the JSON record. Both engine forks are unchanged and clean. The root checkout retains unrelated pre-existing edits. The recorded filesystem reports 100% used and 3.6G available. The cause of the late latency increase remains unmeasured.

## Intake, cycle, and space

Intake rate divides event count by summed durable acceptance time per run. The table gives the median of four rates. Cycle rate also includes cut capture, the input read, and the result/reference/progress commit. Latency percentiles pool all transaction samples. Times are per 256-record transaction. Filesystem allocation is measured after forced maintenance.

| Events | Layout | Intake events/s | Cycle events/s | Intake p50 / p95, ms | Allocated MiB |
| ---: | --- | ---: | ---: | ---: | ---: |
| 16,384 | Long batch | 339,860 | 199,803 | 0.739 / 0.853 | 3.52 |
| 16,384 | Long record | 219,597 | 131,597 | 1.148 / 1.340 | 8.07 |
| 16,384 | Compact batch | 341,366 | 199,445 | 0.739 / 0.843 | 3.52 |
| 16,384 | Compact record | 232,763 | 136,628 | 1.066 / 1.259 | 6.77 |
| 262,144 | Long batch | 336,338 | 194,671 | 0.747 / 0.853 | 53.54 |
| 262,144 | Long record | 216,542 | 131,029 | 1.198 / 4.586 | 128.48 |
| 262,144 | Compact batch | 334,037 | 192,874 | 0.754 / 3.946 | 53.28 |
| 262,144 | Compact record | 229,944 | 135,182 | 1.093 / 1.259 | 107.12 |

The large compact record cycle median is 29.91% below compact batch. Compact record intake is 6.19% above long record in the four-run medians. The compact record keys use 4.00 MiB instead of 20.25 MiB. Event value bytes do not change. These medians do not establish a general insertion-speed benefit from compact keys.

## Reads

Point clocks include snapshot capture, native lookup, CRC/canonical decode, and result construction. They stop before exact-output verification. Scan clocks include exact-byte and position verification. Each point phase follows a full scan. These are not cold disk point reads. The point workload selects one cursor per prepared batch, as in the earlier raw pilot.

| Events | Layout | Warm scan, million events/s | Reopened scan | Reopened point p50 / p95, µs |
| ---: | --- | ---: | ---: | ---: |
| 16,384 | Long batch | 5.868 | 5.681 | 20.394 / 26.680 |
| 16,384 | Long record | 1.652 | 1.541 | 3.283 / 5.308 |
| 16,384 | Compact batch | 7.021 | 6.194 | 12.990 / 14.387 |
| 16,384 | Compact record | 1.721 | 1.591 | 3.282 / 6.496 |
| 262,144 | Long batch | 8.342 | 5.716 | 26.680 / 32.896 |
| 262,144 | Long record | 1.394 | 1.495 | 4.819 / 8.171 |
| 262,144 | Compact batch | 8.301 | 5.812 | 26.470 / 33.874 |
| 262,144 | Compact record | 2.158 | 1.568 | 4.400 / 7.752 |

## Retained latency events

The final two large-workload processes have much higher write latency. They are the fourth compact-batch run and fourth long-record run. Their cause is unmeasured. No run or sample is removed. The matrix is not rerun to replace them. Pooled p95 and maximum values include both runs.

| Large repetition | Layout | Intake events/s | Cycle events/s |
| ---: | --- | ---: | ---: |
| 1 | Long batch | 338,881 | 197,495 |
| 1 | Long record | 219,157 | 132,155 |
| 1 | Compact batch | 335,718 | 193,866 |
| 1 | Compact record | 229,476 | 134,685 |
| 2 | Long batch | 335,109 | 192,862 |
| 2 | Long record | 217,266 | 131,124 |
| 2 | Compact batch | 334,734 | 193,326 |
| 2 | Compact record | 228,633 | 134,453 |
| 3 | Long batch | 332,765 | 191,929 |
| 3 | Long record | 215,819 | 130,935 |
| 3 | Compact batch | 333,339 | 192,422 |
| 3 | Compact record | 230,412 | 135,680 |
| 4 | Long batch | 337,566 | 196,481 |
| 4 | Long record | 57,904 | 31,265 |
| 4 | Compact batch | 140,266 | 74,527 |
| 4 | Compact record | 237,707 | 139,895 |

Compact record has lower intake and cycle throughput than compact batch in the first three pairs. The fourth compact batch process is slower than the compact record process. The fourth long-record process has 57,904 intake events/s and 31,265 cycle events/s. This run contributes to the long-record pooled p95. Do not treat that p95 difference as an isolated compact-key benefit.

## Space and lifecycle limits

Each compact variant has one source receipt, one epoch row, two mapping rows, and one allocator row. The two maps and extra allocator key/value add 172 live logical bytes for this source. The raw reports retain each group's entry, key-byte, and value-byte counts. Those counts exclude historical versions and engine index/filter blocks. The record event value bytes remain 40.289 MiB across key widths.

Allocated space uses filesystem blocks. Journal statistics report file lengths and can include preallocated space. Neither statistic measures device-write amplification. Forced flush and major compaction are exercised. Background-compaction counters remain zero. Sustained natural compaction and power-loss recovery are not qualified. JSON and raw reports retain reopen, replay, resource, and maintenance metrics.

## Verification and reproduction

The focused release target passes two tests. The partial-history test covers six backends and exact points, bytes, positions, counts, compaction, and reopen. The compact-source test covers two-source ID allocation, unbound reads, replay isolation, compaction, and reopen. All 32 processes pass the existing workload assertions. Changed-file formatting, Python compilation, and the release build pass. Existing library warnings remain. Full CI is not run, as requested.

```sh
cargo test -p araphor-data --release --features test-fixtures --example raw_owner_bench
cargo build -p araphor-data --release --features test-fixtures --example raw_owner_bench
python3 scripts/benchmark_record_storage.py output/araphor-compact-storage-20261113 --compact
```

The PoCs still use immutable append-only rows and logical saved-cut filtering. Native table history, historical receipt updates, deletion, expiry, arbitrary retry/overlap, multi-source global commit-order scans, witness retention, package analysis, and subscription-wake latency remain unqualified. The two-source test qualifies the ID mechanism, not a multi-source performance workload. Production storage and both engine forks are unchanged.

[Machine-readable results](araphor-compact-storage-2026-11-13.json) and [all samples](araphor-compact-storage-2026-11-13.samples.json.gz) retain the measurements. The frozen binary remains in `output/araphor-compact-storage-20261113/raw_owner_bench`.
