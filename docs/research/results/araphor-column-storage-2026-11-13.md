# Packed and separate-column Fjall batches

Measured source: `fd77dc44a`. All 36 measured processes, three smoke processes,
and three focused tests pass. Production and both engine forks are unchanged.

Separate columns improve narrow typed reads. They do not improve the complete
processing rate. They increase allocated space and slow full-schema reads.
These results support a selective-read option, not replacement of every packed
batch with separate columns.

## Intended end state

Measure the [proposed table layout](../../designs/araphor-table-storage.md)
against packed Arrow IPC with native projection. Keep the original bytes,
schema, keys, journal, input progress, and durability the same. Use the existing
RawCommit payload codec as a separate representation reference.

## Matched conditions

| Condition | Stored batch | Query preparation |
| --- | --- | --- |
| Frames | One header and one RawCommit value | Original-record reads avoid protobuf decoding. Typed reads decode records and construct Arrow arrays. |
| Packed Arrow | One header and one IPC value with five varying columns | Uses Arrow's native reader projection. Caches the fetched value within each page. |
| Separate columns | One header and five single-column IPC values | Fetches and materializes requested columns independently. |

The six SQL columns are CPU, source cursor, task cookie, operation, kernel
result, and original framed record. CPU is a batch constant. The other five
columns use arrays. The RawCommit reference keeps its required legacy revision
field at 1. That field is not used for processing order or progress. This
condition is not the complete current production owner or its extraction path.

Each condition has four real Fjall keyspaces: catalogue, events, benchmark
output, and benchmark progress. The natural batch key contains node, source,
source epoch, and first source cursor. It has no tenant or table-name prefix.
One progress record maps the subscription to the native input cursor.
There is no sources table, application revision counter, or copied CDC archive.

Input sizes are 16,384 and 262,144 records, with 256 records per batch. The large
input contains 37,445,318 original framed bytes in every condition. Successive
batches use four CPU values. The CPU filter selects one quarter of the rows.
Original framed bytes are unchanged. All six condition permutations run at
each size. Each of the 36 processes creates a fresh store.

Ingestion includes required frame decoding, Arrow construction, encoding, and
one SyncAll commit. The timed cycle then walks the original journal, reads the
new input through the saved native plan, and commits output and consumed input
cursor in another SyncAll transaction. Planning occurs separately.

## Write and complete-cycle results

Rates are medians of six process rates. Space is the median allocated size
after forced flush and major compaction, before first owner close.

| Records | Condition | Intake events/s | Complete cycle events/s | Allocated MiB |
| ---: | --- | ---: | ---: | ---: |
| 16,384 | Frames reference | 369,626 | 164,802 | 3.355 |
| 16,384 | Packed Arrow | 285,839 | 159,199 | 4.059 |
| 16,384 | Separate columns | 283,783 | 159,060 | 4.645 |
| 262,144 | Frames reference | 357,553 | 159,153 | 52.375 |
| 262,144 | Packed Arrow | 272,578 | 153,475 | 63.590 |
| 262,144 | Separate columns | 264,805 | 150,943 | 72.992 |

For the large input, the paired separate/packed cycle-rate ratio has median
0.991 and range 0.924..1.031. Its intake-rate ratio has median 0.983 and range
0.889..1.028. These mixed differences establish no write or cycle gain.

The last three large processes slow down in all conditions: approximately
32,583 events/s for separate columns, 31,594 for packed Arrow, and 34,315 for
Frames. The cause is unmeasured. Keep all samples. Do not infer a tail-latency
improvement from this matrix. No build or other agent benchmark runs during
measurement. Other host activity is not controlled.

### Per-batch latency at 262,144 records

The table pools 6,144 observations per condition. Values are milliseconds.
`Cycle` includes both durable commits, original-log traversal, and input read.

| Condition | Intake median / p95 / max | Cycle median / p95 / max |
| --- | --- | --- |
| Frames | 0.710 / 3.679 / 5.091 | 1.588 / 7.526 / 10.144 |
| Packed Arrow | 0.924 / 4.304 / 7.192 | 1.641 / 8.237 / 11.840 |
| Separate columns | 0.958 / 4.195 / 7.888 | 1.671 / 7.960 / 14.921 |

Space includes retained original WAL files and the held middle snapshot. It
is not post-GC or steady-state space. Separate columns use about 14.8% more
allocated space than packed Arrow and about 39.4% more than this Frames
reference. The event key/value totals are 83,968 / 45,983,102 bytes for packed
Arrow and 262,144 / 47,129,982 bytes for separate columns. Thus the separate
layout has more keys and IPC framing even though both retain the same arrays.
This experiment does not isolate each cause of the physical-space difference.

## Read results at 262,144 records

These are whole-query times after owner reopen. They are not cold disk reads.
Values are median / p95 milliseconds from six observations. With six
observations, the empirical p95 equals the maximum. All stages and minimums
remain in the structured record.

| SQL read | Frames reference | Packed Arrow | Separate columns |
| --- | ---: | ---: | ---: |
| All six columns | 114.221 / 119.148 | 26.255 / 26.355 | 39.733 / 39.982 |
| Source cursor and original record | 27.027 / 27.181 | 17.651 / 18.038 | 19.251 / 19.673 |
| Source cursor and task cookie | 103.984 / 106.874 | 16.209 / 16.446 | 8.489 / 8.819 |
| Same two columns, CPU = 2 | 30.353 / 31.246 | 7.592 / 7.669 | 5.792 / 6.057 |
| CPU = 2 and task cookie modulo 7 = 0 | 31.645 / 33.001 | 9.499 / 9.614 | 6.942 / 7.527 |
| Original record with both filters | 32.089 / 35.490 | 9.995 / 10.308 | 10.334 / 10.847 |

The paired packed/separate time ratios have these medians and ranges:

| Read | Separate-column speed ratio | Pair range |
| --- | ---: | ---: |
| All columns | 0.662 | 0.655..0.677 |
| Original records | 0.915 | 0.904..0.933 |
| Two numeric columns | 1.904 | 1.827..1.994 |
| CPU-filtered numeric columns | 1.310 | 1.255..1.408 |
| CPU and varying-column filter | 1.367 | 1.277..1.424 |
| Filtered original records | 0.967 | 0.903..0.974 |

The large narrow-read gain is consistent across all six pairs. Full and
original-record reads are consistently slower than packed Arrow. Differences
against Frames also include the cost of decoding protobuf into typed columns;
they are not evidence of a column-layout-only gain.

### What the read counters prove

Every count below is identical across the six matching runs. The public
record verifies that equality rather than assuming it from the first run.

| Read and layout | Logical value reads | Requested value bytes | IPC arrays materialized |
| --- | ---: | ---: | ---: |
| Two numeric columns, packed | 2,048 | 45,983,102 | 2,048 |
| Two numeric columns, separate | 3,072 | 5,137,918 | 2,048 |
| CPU-filtered numeric columns, packed | 1,280 | 11,503,102 | 512 |
| CPU-filtered numeric columns, separate | 1,536 | 1,291,774 | 512 |

Separate numeric columns reduce requested value bytes by about 88.8%. Both
layouts already use native IPC projection and materialize the same selected
arrays. The separate layout makes more KV lookups. CPU pruning skips 75% of
the payload batches in both conditions without a secondary CPU index.

`Logical value reads` includes header-iterator items. `Requested value bytes`
means uncompressed encoded values returned by KV calls. It does not mean
physical device or SST block I/O. `IPC arrays materialized` counts projected
IPC columns, not all parsing, buffer allocation, decompression work, or
generated constant arrays. No claim of independent SST-block reads is made.

## Source review and verification

[The runner](../../../scripts/benchmark_column_storage.py) starts each fresh process
  -> [The example](../../../crates/araphor-data/examples/table_storage_bench.rs) prepares the original fixtures and saved native SQL plans.
  -> [Table::append](../../../crates/araphor-data/src/analysis/native/benchmark/columnar.rs) encodes and atomically commits a header and its payload values.
  -> [The cycle](../../../crates/araphor-data/examples/table_storage_bench.rs) reads the original journal until one input header supplies its exact cursor and key.
  -> [Source::open](../../../crates/araphor-data/examples/table_storage/provider.rs) applies native pruning and physical predicates before projected-column reads.
  -> [Page::read](../../../crates/araphor-data/src/analysis/native/benchmark/columnar.rs) loads columns through native Arrow IPC projection.
  -> [Table::complete](../../../crates/araphor-data/src/analysis/native/benchmark/columnar.rs) commits benchmark output and the observed input cursor atomically.

[The example](../../../crates/araphor-data/examples/table_storage_bench.rs) closes and reopens the owner
  -> Saved progress still identifies the input commit, not the later output commit.
  -> Original-log replay returns exact expected batch keys in commit order.
  -> Each replay descriptor resolves to exact typed rows and original bytes.
  -> A later append wakes the native feed and returns the exact continued rows.

The [three focused tests](../../../crates/araphor-data/examples/table_storage/tests.rs)
check the raw-only codec path, mixed-CPU filtering, native IPC projection,
transaction abort, an alternate schema without CPU, and native SQL null and
string predicates. The three CLI smoke processes and all 36 measured
processes check exact rows, original bytes, held-view contents, native input
progress, close/reopen, replay, and continuation. Formatting, Python syntax,
and the corrected distribution self-check pass. Existing library warnings
remain. Full CI is not run, as requested.

The first runner summary used the upper middle observation as its median.
After measurement, aggregation uses the conventional median of the original
samples and checks that row/read counters match across runs. The executable
and timing observations are unchanged. The archive preserves the original
summary. The public JSON records this correction and the aggregation source
hash.

Query order is fixed: full, raw, projected, CPU, residual, filtered raw.
Full reads can warm later queries. Measurement runs retain the OS page cache.
Snapshots and source bindings are specific to this fixture. Durable historical
table reads, schema evolution, complete collector admission, retry/gap/expiry
semantics, sustained compaction, power loss, Graph, packages, and notification
latency are not qualified. The 100-fold incident goal is not measured here.

## Result and reproduction

Keep packed batches as the general default on this evidence. Consider
separate columns for frequent narrow typed reads when the measured read gain
justifies extra space and write work. Do not apply the separate-column layout
to production solely from this fixture.

```sh
rtk proxy cargo test -p araphor-data --release --features test-fixtures --example table_storage_bench
rtk proxy cargo build -p araphor-data --release --features test-fixtures --example table_storage_bench
rtk proxy python3 scripts/benchmark_column_storage.py output/araphor-column-repeat
```

[Structured measurements](araphor-column-storage-2026-11-13.json) contain all
36 runs, conventional summaries, pair ratios, source and binary hashes, engine
commits, compiler, host, and filesystem. [Raw samples and logs](araphor-column-storage-2026-11-13.samples.json.gz)
contain 117 files. Archive SHA-256:
`5f9499aa539853a7f265a6a231c452e2e4358d8e4c05755a549615a21ca3bfc8`.
The frozen executable and working output remain under
`output/araphor-column-storage-20261113/`.

Result: **Done for the approved benchmark and its measured comparison.
Production table implementation and qualification remain Not done.**
