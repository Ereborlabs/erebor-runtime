# General tables on Fjall

This design defines tables for collector data with different schemas. It adds
a common table layer in Data and a native DataFusion reader. Fjall remains the
storage engine. This document does not change its branch or history design.
It supports item 2 of the [storage investigation](../plans/araphor-data-storage-and-collectors.md).

Status: **Proposed for production.** The user approves a benchmark of this
layout after the worked storage example. The implementer and reviewer agree
on the comparison below. Production implementation is not approved or started.

## Intended end state

A collector supplies typed batches to its table. Data stores each batch once
in column chunks inside that table's Fjall keyspace. A query reads the columns
it needs. A subscription reads new committed inputs from the existing journal
reader and uses its saved native cursor. Packages receive the selected rows
and use the existing Data transaction for their changes.

CPU, node, source, and timestamp are columns of schemas that need them. They
are not required fields in every table. There is no tenant field. One table
does not require one source, CPU, or collector instance.

## What the database comparison supports

These are design lessons, not comparative performance results.

| System | Relevant behavior | Application here |
| --- | --- | --- |
| [GreptimeDB Mito](https://docs.greptime.com/contributor-guide/datanode/storage-engine/) | Sorts data by tags and time. Uses columnar Parquet SSTs, row-group statistics, and indexes. | Use typed columns, batch statistics, and selective reads. Keep Fjall's existing SSTs. |
| [InfluxDB 3](https://docs.influxdata.com/influxdb3/clustered/reference/internals/storage-engine/) | Uses Arrow and DataFusion. Queries include recent ingester data before Parquet persistence. | Feed Arrow batches to native plans. Do not wait for a large file or time window before processing a committed batch. |
| [QuestDB](https://questdb.com/docs/concepts/partitions/) | Stores columns separately within time partitions. Its [indexes](https://questdb.com/docs/concepts/deep-dive/indexes) locate rows for selected symbol values. | Store independently readable columns. Add an index only for an access path that needs it. |
| [TimescaleDB](https://www.tigerdata.com/docs/build/performance-optimization/secondary-indexes) | Separates grouping columns (`segmentby`) from ordering columns (`orderby`). Groups rows in compressed column batches. Small groups reduce compression efficiency. | Store batch constants once. Do not split every identifier into tiny groups or wait for a target group size. |
| [ClickHouse MergeTree](https://clickhouse.com/docs/reference/engines/table-engines/mergetree-family/mergetree#data-storage) | Uses sorted parts and sparse marks. Compact parts pack small inserts together; wide parts separate columns. | Keep batch writes. Measure the extra cost of separate column values against one packed value. |

We do not adopt a separate TSDB, its WAL, or its file lifecycle. Event time
does not define committed processing order. A late event must still appear
after its native journal position. A general table need not have a timestamp.

The local GreptimeDB material found during this review is a Git cache at
`/home/navid/.cache/com.sourcegraph.cody/repos/github.com/greptimeteam/greptimedb`.
Its head is `395632c874a84a2801da28553c4f83ef27932508`, dated 2023-11-03.
Its `src/mito2/src/memtable.rs` accepts projections and predicates. Its
`src/mito2/src/sst/parquet/reader.rs` prunes row groups and projects columns.
Current behavior above comes from the linked official documentation and
[current bulk-memtable source](https://github.com/GreptimeTeam/greptimedb/blob/main/src/mito2/src/memtable/bulk.rs).
The old cache does not prove the current implementation.

## What is stored

### 1. One table definition

A small catalogue record holds the table name, its Fjall keyspace identity,
Arrow schema, stable column IDs, schema version, and declared indexes.
The table name is not repeated in each data key. A column ID identifies a
field within that table; it is not a table name or a source-ID allocation.

The definition selects append batches for collector events, or primary-key
rows for mutable state. The same schema, transaction, and DataFusion contracts
apply. Updating one state row must not rewrite an event batch. This design
does not rewrite Graph's representation or analysis facilities.

A primary-key row uses `R | primary_key -> schema version and encoded row`.
Reuse the current record codec for these small rows. Index changes share the
same transaction. Fjall supplies row versions; do not append a revision to
each user key.
Reading such a row still reads its encoded value. Independent column reads
apply to the append layout below, not to the small-row codec.

### 2. One small header per batch

Each append has an immutable batch key supplied by its intake adapter.
For the existing BPF stream, use `(node_id, source_id, source_epoch, first_cursor)`.
Another collector can use its own stable producer identity and batch position.
It does not need CPU or BPF source fields.

The header holds schema version, row count, batch constants, and statistics
for columns selected for pruning. BPF constants include CPU and the existing
boot and label bindings. The source cursor column preserves exact record
positions. It replaces a separate list of spans for this contiguous batch.
Do not invent contiguous positions for a collector whose positions have gaps.

An index or statistic must not remove the adapter's existing identity, gap,
retry, or expiry checks. The generic table layer does not decide those rules.

### 3. One value per nonconstant column chunk

In the table's own keyspace, the logical layout is:

```text
H | batch_key              -> small batch header
C | column_id | batch_key  -> Arrow IPC column chunk
```

`H` and `C` are local record tags. They are not table-name prefixes. Header
scans visit only `H` records. Column reads address `C` records directly.
Use the existing Arrow IPC library; do not create another column codec.
The key examples show typed tuples, not concatenated display strings.
Column dictionaries must be readable with their chunk after restart.

For 256 rows and five varying columns, this is one header and five column
values for the batch. It is not six metadata rows per event. Constant columns
come from the header. DataFusion receives ordinary Arrow arrays for them.
Keep input row order and stable row positions across all columns.
Nested Arrow fields remain in their containing column chunk. Independent
reads of nested leaves would require a separate layout decision.

If a batch exceeds supported value or execution sizes, divide it into aligned
row groups. Include the group number in each key. Commit the groups together.
Do not discard rows or wait for more input to fill a group. Group sizing is a
measurement choice, not a storage quota.

Original evidence bytes, when required by the existing contract, are one
`Binary` column containing the original framed records. A query that does
not request it does not decode it. Parsed query columns are derived data and
have a real storage and ingestion cost. They are not free. Other collectors
need no raw column unless their contract requires original bytes.
There is no second raw archive or segment-file write.

Separate values permit separate KV reads and column decoding. Fjall can still
read an SST block that contains other values. This is not a claim that Fjall
has acquired GreptimeDB's columnar SST format or zero-copy disk reads.

## One BPF batch, step by step

```text
Node A sends an existing batch from CPU 3, source S, epoch E, cursors 1001..1256
  -> The existing intake owner checks authentication, identity, and retry rules.
  -> The BPF adapter supplies batch key (A, S, E, 1001).
  -> The adapter builds the table's declared Arrow columns once.
  -> Data stages the header, columns, and configured indexes in one transaction.
  -> Fjall durably commits the transaction and returns its native cursor L.
  -> Data acknowledges the accepted input through the existing intake contract.
  -> The existing journal reader observes the committed header and columns.

A package definition selects rows WHERE cpu_id = 3 AND pid = 42
  -> The saved plan's source filter tests CPU against the new header constant.
  -> A CPU 2 batch does not require a PID or raw-column read for this filter.
  -> A CPU 3 batch supplies its PID column to DataFusion's native expression.
  -> The reader loads remaining projected columns for batches with selected rows.
  -> DataFusion passes the selected rows to the package call, if one is present.
  -> A filter-only definition returns its selected rows without a package call.
  -> The package stages its chosen state, Graph changes, and findings.
  -> Data commits those changes and processed input cursor L together.
```

Reading predicate columns before remaining columns follows the
[ClickHouse PREWHERE pattern](https://clickhouse.com/docs/concepts/features/performance/prewhere).
Each selected column chunk still contains all rows in its row group. This
layout does not promise row-addressed disk reads within that value.

The output commit has its own cursor. It must not replace consumed input L.
Progress remains one processed-through native cursor per subscription in its
existing storage context. It has no source, CPU, branch-name, or finding-ID key.
This supersedes the natural-schema PoC's per-source latest-result frontier as
a target design. It does not change that experiment's measured record.

The journal contains the original transaction. There is no table CDC archive.
The table reader recognizes the header as the batch descriptor; column and
index writes do not cause separate package calls. It evaluates remaining
source filters before it reports matching input. Shared-journal traversal can
still read unrelated journal bytes. This design avoids unrelated payload
decoding and package execution; it does not claim a separate physical log for
each predicate.

## How a different collector fits

For example, a future collector could define:

```text
service_logs: received_at, node_id, service, severity, message
host_metrics: observed_at, node_id, device, temperature
```

These are example schemas, not claims that these collectors exist. Each uses
the same append, column, filter, and transaction path. A batch can contain
different services, devices, or CPUs. Only columns that are constant in that
batch can be answered from its constants. Otherwise, read the predicate column
and evaluate the ordinary DataFusion expression.

An absent field in one collector is not a null field forced into every other
collector. SQL can join separate tables or use a view when their schemas have
a useful relationship. Saved plans use the existing schema-dependency rules.
Stable column IDs keep stored chunks tied to their schema version. A type
change must not silently reinterpret retained data.

## Indexes and query execution

Start with batch headers and column reads. An optional secondary index has its
own Fjall keyspace. For historical CPU lookups on naturally single-CPU batches:

```text
CPU index: (cpu_id, batch_key) -> empty
```

One index entry locates one batch. `cpu_id = 3` can seek this key range without
opening CPU 2 headers or raw values. This is an index, not another event copy
or a sources table. It is unnecessary for a CDC batch whose header is already
available. Add it only when the required historical access path justifies its
write and space cost.

An index used for an entire query must cover every eligible batch. A mixed-CPU
batch needs entries for its represented CPU values, or a fallback scan. Index
candidates still require row filtering when the batch contains other values.
Do not assume one CPU per batch as a general table rule.

Min/max and null counts can skip batches. Use DataFusion's existing
`PruningStatistics` and `PruningPredicate`, then its physical expressions for
row predicates. Unknown statistics keep a batch eligible. Do not write a
second SQL evaluator. A general range index for varying columns can require
more entries than a batch-constant index; it is not included automatically.

One schema-driven `TableProvider` uses the existing `DataSourceExec` path.
It reads predicate columns and projected columns, not every table column.
Statistics-only pruning is `Inexact`; retain the exact residual filter.
Advertise `Exact` only when every returned row satisfies the predicate.
Apply a pushed limit after exact filtering. These are the
[DataFusion 55 provider contracts](https://docs.rs/datafusion/55.0.0/datafusion/datasource/trait.TableProvider.html),
the version used by this repository. Native joins, aggregation, and package
functions remain in the current execution owner. A table reader does not make
every SQL operation incrementally maintained by itself.

## Proposed API and change owners

These are proposed operations, not existing public methods:

| Operation | Owner and effect |
| --- | --- |
| `define_table(tx, definition)` | Data saves the schema and keyspace binding. |
| `table.append(tx, batch_key, RecordBatch)` | Stages one immutable collector batch and its declared indexes. |
| `table.upsert(tx, RecordBatch)` / `table.delete(tx, keys)` | Stages primary-key state rows and associated index changes. It does not rewrite collector batches. |
| `table.provider(read_view)` | Query constructs the native provider for one existing consistent read view. |
| Existing committed-input reader | Supplies changed batch descriptors and native input cuts to the same provider. |

No table or package method commits the transaction. Data alone commits it.

The main implementation sites are Data's
[table schema catalogue](../../crates/araphor-data/src/analysis/extraction/tables/schema.rs),
[native event storage](../../crates/araphor-data/src/analysis/native/events/mod.rs),
and Query's [source provider](../../crates/araphor-query/src/sources/mod.rs) and
[change reader](../../crates/araphor-query/src/sources/journal.rs).
Replace event-specific schema and extraction dispatch with table definitions
and adapters. Keep BPF validation at its current intake owner. Port event,
diagnostic, managed-input, and public SQL callers together when implementation
is approved. Registering a new collector transport remains investigation item 3.

Do not add a generic sources table merely to list producers. Retained event
keys and headers already identify them. Keep whatever existing intake owner
must preserve for contiguous ACKs, gaps, immutable bindings, and expired retry
frontiers. Deleting retained events must not erase those promises. Removing
that metadata requires proof of an equivalent remaining owner.

## Verification before adoption

Required correctness covers two different schemas, mixed-value batches, SQL
result parity, null predicates, projection, atomic rollback, exact retries,
gaps, expiry, historical reads, restart, and continued original-journal replay.
Verify column and index visibility at the same committed cut. Confirm that
CPU filtering does not decode the original record column. Retention and restore
must preserve referenced chunks, schema versions, and pending input positions.
Fjall continues to supply its existing lifecycle guarantees.

The packed-batch PoC remains the performance control. Reuse its successful
16,384 and 262,144-event workloads, 256-record batches, durability boundaries,
byte checks, and reopen checks. Compare the unchanged original-payload read
and full cycle. Separately propose narrow-column, CPU-filter, and mixed-schema
read cases. Report keys, encoded bytes, actual read bytes, decoded columns,
write/cycle throughput, and median/p95/maximum latency with matched builds.
New benchmark cases require user approval before development or execution.

### Approved benchmark comparison, 2026-11-13

The user requests this benchmark explicitly. Compare packed Arrow IPC with
separate column IPC on the same schema, headers, keys, native input cursors,
and two SyncAll transactions per processing cycle. A third condition uses the
existing RawCommit payload codec. It is a representation reference, not the
layout-only control or the complete production owner.

Reuse 16,384 and 262,144 original fixture records and 256-record batches. Assign
successive batches to four CPUs identically in all conditions. Original framed
bytes remain unchanged. Run all six condition orders at each size: 36 fresh
processes. Each process has a finite record count. Runtime is recorded; no
latency threshold or timeout change is introduced.

Ingestion includes frame decoding, Arrow construction, encoding, and durable
commit where each condition needs them. Packed IPC uses Arrow's native reader
projection. Measure full, original-record, projected, CPU-filter, residual,
and filtered-original-record SQL reads. Reuse saved native plans. Record
planning separately. Queries run in that fixed order before maintenance,
after forced maintenance, and after owner reopen. Reopen is not cold disk I/O.

Correctness requires exact bytes and SQL rows, a second schema, SQL null and
string predicates, mixed-CPU batches, atomic abort, held snapshot reads,
persisted input-cursor progress, exact original-journal replay, and continued
publication. Timings are report-only. Count requested KV values, value bytes,
IPC columns materialized, and protobuf records decoded. These counters do not
measure physical block or device I/O. Full CI remains excluded by user request.

The [latest measured natural-schema PoC](../research/results/araphor-natural-batch-storage-2026-11-13.md)
measures metadata simplification, not this column layout. Its results do not
prove this design faster or smaller. Separate column IPC values can cost more
to write than one packed value. Keep the simpler packed layout if selective
reads do not justify that cost on the approved workload. No new latency or
throughput number is claimed here.

Result: **Done for the proposed design and source review. Not done for
implementation, benchmark approval, or performance qualification.**
