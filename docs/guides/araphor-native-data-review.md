# Native Data transaction review

This guide covers the optional native Data owner, raw source storage, and its
package storage proof of concept (PoC) caller. The metadata source follows
Runtime `78e909526`. The combined raw view follows `f05f444e2`.
Production Data still uses DuckDB. Read the [integration research](../research/araphor-fjall-integration.md)
for the complete migration.

## Intended end state

Data owns the raw and metadata publication boundary. One native transaction
commits Graph, findings, state, references, and consumed positions. Original
logs supply selective subscription wakes. Native DataFusion plans read one
consistent view. The complete migration remains **Not done**.

## Review flow

[NativeStore::open](../../crates/araphor-data/src/analysis/native/mod.rs) Data opens the native metadata store
  -> [AnalysisLease::acquire](../../crates/araphor-data/src/analysis/connection.rs) Data takes the existing private-directory lease.
  -> [NativeStore::open](../../crates/araphor-data/src/analysis/native/mod.rs) Data restores the branch and checks durable history protection.
  -> [NativeStore::cut_view](../../crates/araphor-data/src/analysis/native/mod.rs) Data opens the exact stamped cut and checks its Data revision and store identity.
  -> [NativeStore::recover_raw](../../crates/araphor-data/src/analysis/native/source/raw.rs) Data recovers the original segments and their metadata controls.
  -> [NativeStore::view](../../crates/araphor-data/src/analysis/native/mod.rs) Data exposes the published immutable raw and metadata view.

[Live::apply](../../crates/araphor-graph/examples/storage_poc/live.rs) The existing package PoC prepares a step
  -> [View::prepare](../../crates/araphor-graph/src/native/prepare.rs) Araphor Graph prepares the package journals.
  -> [NativeStore::write](../../crates/araphor-data/src/analysis/native/mod.rs) Data serializes the writer and proposes the next Data revision.
  -> [Graph::stage](../../crates/araphor-graph/src/native/write.rs) Araphor Graph stages its records in the supplied transaction.
  -> [DataWrite::context](../../crates/araphor-data/src/analysis/native/context.rs) Data stages physical immutable context records and their heads.
  -> [Live::apply](../../crates/araphor-graph/examples/storage_poc/live.rs) The PoC stages its synthetic step metadata and consumed cursor.
  -> [DataWrite::commit](../../crates/araphor-data/src/analysis/native/mod.rs) Data commits all records and exact cut stamps in one native batch.
  -> [DataWrite::commit](../../crates/araphor-data/src/analysis/native/mod.rs) Data publishes the matching metadata view after durable commit.

[Walker::start](../../crates/araphor-graph/examples/storage_poc/cdc.rs) The existing journal walker reads committed source and Graph changes
  -> The native feed can wake after engine commit and before Data publishes its view.
  -> The PoC waits for `DataWrite::commit` to return before it consumes results.
  -> The production routing barrier remains **Not done**.

[DataWrite::rollback](../../crates/araphor-data/src/analysis/native/mod.rs) A step rolls back
  -> [BranchWriteTransaction::rollback](../../fjall/src/versioned/write.rs) The engine discards all staged records.
  -> [NativeStore::view](../../crates/araphor-data/src/analysis/native/mod.rs) The published view and Data revision stay unchanged.

[DataWrite::commit](../../crates/araphor-data/src/analysis/native/mod.rs) A native commit or publication fails
  -> [NativeStore::check](../../crates/araphor-data/src/analysis/native/mod.rs) Data stops new captures and writes.
  -> [NativeStore::open](../../crates/araphor-data/src/analysis/native/mod.rs) Reopen restores confirmed durable state.

## Owners and coordinates

```mermaid
sequenceDiagram
    participant C as PoC caller
    participant D as Data
    participant G as Araphor Graph
    participant F as Fjall
    C->>G: Prepare package journals
    C->>D: Begin write
    D-->>C: DataWrite
    C->>G: Stage with borrowed transaction
    C->>D: Stage context records
    C->>D: Commit
    D->>F: Commit records and cut stamps
    F-->>D: Durable revision and cursor
    D->>F: Open exact committed cut
    D-->>C: Publish view and return receipt
```

`Live` is the PoC caller. Package code returns journals and state. Package code
receives no `NativeStore` or `DataWrite`. Graph receives a borrowed native
transaction and cannot consume that transaction to commit it.

`NativeStore` owns the engine, live branch, Data writer lock, store identity,
readiness, published view, and directory lease. `DataWrite` holds the writer
until commit and publication finish. A reader clones an `Arc<DataView>` under
a short read lock. A reader does not wait for the Data writer.

Initialization publishes Data revision 0. The first ordinary commit uses
revision 1. The proposed Data revision becomes consumed only on commit. An identical
context retry returns the original reference. That retry alone creates no
batch and does not advance Data progress.

The PoC's sparse Graph revisions remain fixture coordinates. Its `cut/` records
map those coordinates to allocated Data revisions. Data's `\0data/cut/` records
map allocated revisions to exact native cuts. Graph layer cut stamps remain
native cuts. The PoC does not inject its fixture numbers into Data's allocator.
Graph row origins also remain fixture coordinates. This caller does not qualify
production Data origin or managed reference validation.

The PoC's source, output, and checkpoint writes use this Data owner. Current
reads use its published view. Original journal readers remain unchanged.
The fixture's synthetic source records do not qualify production raw admission
or managed authority.

## Physical context records

The context participant reuses `AnalysisContextVersionV1` and
`AnalysisContextRefV1`. It checks immutable identity, exact retries, and expected
heads. It does not replace qualified owner, package provenance, fact, import,
notification, or lifecycle admission.

The `\0data/key/` dictionary interns exact serialized identities. Long keys use
linked fragments at the engine key width. No content hash selects identity.
`\0data/C` records hold immutable versions. `\0data/H` records point to the
highest owner revision for one context identity. Native snapshots select their
historical values. Value fragments use the engine value width.

The first caller stores its existing package state and captured frontier as
context versions. It removes the previous PoC `S`, `T`, and `H` records. State,
frontier, Graph, and cursor assertions retain their original meaning.

This owner currently retains the initial Data cut through future cuts. Startup
rejects a store whose required protection is absent. Data retention floors,
capacity accounting, and collection policy are not implemented here.

## Verification and limits

[Native Data tests](../../crates/araphor-data/tests/native_store.rs)
cover rollback, exact retries, context heads, joint Graph/context/progress
batches, exact stamps, captured readers during a write, long binary keys,
invalid commit recovery, compaction, reopen, and interrupted initialization.
Five public-API integration cases pass for the final source. See the
[qualification](../../crates/araphor-graph/examples/storage_poc/results/native-data-2026-11-09/README.md)
for commands, exact source hashes, and limits.

The unchanged combined and stable PoCs supply the cross-crate caller checks.
The final source passes 128 stable cycles, 640 historical package evaluations,
320 historical views, and eight combined runs. The complete comparison interval
includes Data publication and context-version records. The reported `output_sync_s`
field includes the Data commit and publication call; it does not isolate sync
time. Stable-key checks cover Graph indexes and context heads. They do not
assert a fixed count of immutable context versions.

Production raw-prefix publication, read admission and memory budgets, qualified context
checks, managed source authority, complete result families, production log
routing, notification batching, retention, and backup remain **Not done**.
The earlier Data unit-test target cannot build its unchanged legacy fixtures.
Clippy stops on unchanged legacy `unwrap` and `expect` calls. These checks
remain **Not done**. The incident performance test and full workspace CI have
not run for this change. No incident speedup is established.

## Data schema initialization

[AnalysisStore::open](../../crates/araphor-data/src/analysis/mod.rs) Data creates its current store
  -> [Relations::schema](../../crates/araphor-data/src/analysis/graph_rows/store/relations/schema.rs) One factory assembles the existing Data and Araphor Graph schemas.
  -> [Relations::SCHEMA](../../crates/araphor-data/src/analysis/graph_rows/store/relations/schema.sql) The common Graph schema also creates the canonical fact index.
  -> [Relations::validate_tables](../../crates/araphor-data/src/analysis/graph_rows/store/relations/schema.rs) Validation compares all Graph columns, constraints, and views against that factory.

The previous expected schema omitted seven engine tables and the fact-index
table. A new Data store failed before raw operations. The correction uses the
same table definitions and keeps the full comparison. The
[public regression](../../crates/araphor-data/tests/store_schema.rs) passes
open, data validation, and reopen. An unexpected Graph table still makes reopen
fail. The command is `cargo test --offline -p araphor-data --features test-fixtures --test store_schema`.
The local check also enabled `native-store` and used the recorded link override.
This correction establishes no performance gain or production engine migration.

## Shared raw metadata

[RawJournal::append](../../crates/araphor-data/src/analysis/raw_segments.rs) Data accepts a raw append
  -> [RawJournal::prepare_index](../../crates/araphor-data/src/analysis/raw.rs) Data builds the next metadata root before file I/O.
  -> [RawIndex::prepare](../../crates/araphor-data/src/analysis/raw/index.rs) The next root shares unchanged ordered tree paths.
  -> [RawJournal::append](../../crates/araphor-data/src/analysis/raw_segments.rs) The existing segment append and sync complete.
  -> [RawJournal::append](../../crates/araphor-data/src/analysis/raw_segments.rs) Data publishes the prepared root after the durable checks.

[AnalysisStore::read_tables_inner](../../crates/araphor-data/src/analysis/extraction.rs) A reader needs source range metadata
  -> [RawIndex::source_state](../../crates/araphor-data/src/analysis/raw/index.rs) The reader clones the root under the raw lock, releases the lock, and scans the captured ranges.
  -> [RawIndex::selection_revision](../../crates/araphor-data/src/analysis/raw/index.rs) Dependency reads use the same capture rule.

`RawJournal` owns one `RawIndex` for sources, entries, ranges, and the latest raw
revision. The three maps use `rpds` ordered trees with shared ownership.
Segments, current paths, file usage, allocation, directory stamps, and admission
budgets remain in `RawJournal`. A captured root contains metadata, not payloads
or open files. File selection still resolves segment IDs through the live owner
and takes the existing finite read lease. Captured metadata does not prevent
retention from deleting raw files.

The existing raw format, append/sync boundary, SQL projection, recovery, and
admission remain in use. The Arrow inputs and DataFusion interfaces do not
change. No extra journal, payload archive, or Fjall write is added for an append.
The complete production raw/native Data view and CDC routing remain **Not done**.

The [raw integration cases](../../crates/araphor-data/tests/raw_index.rs) use the
actual shared roots through a `test-fixtures` helper. Public Data operations
check out-of-order input, retries, conflicts, receipt changes, selection,
positions, rotation, retention, reopen, and failed-append recovery. The helper
is absent from the normal production API. No raw latency gain is established.

The [qualification](../research/results/araphor-raw-index-2026-11-09.md) records
nine passing integration cases, the feature-off build, and the unchanged
incident. Its single timing run does not establish a gain. Production remains
on DuckDB. Clippy stops on two unchanged legacy calls; full CI does not run
during iteration.

## Combined native and raw view

[NativeStore::accept_validated_batch](../../crates/araphor-data/src/analysis/native/source/raw.rs) Data receives an Evidence batch
  -> [ValidatedEvidenceBatchV1::validate_identity](../../crates/araphor-data/src/analysis/mod.rs) The shared validator checks identity and frame bounds.
  -> [RawJournal::prepare](../../crates/araphor-data/src/analysis/raw.rs) The existing owner checks source binding, overlap, and exact retry bytes.
  -> [RawJournal::append](../../crates/araphor-data/src/analysis/raw_segments.rs) The existing segment append and durable sync finish.
  -> [NativeStore::accept_validated_batch](../../crates/araphor-data/src/analysis/native/source/raw.rs) Data publishes the new global revision and raw root with the previous native snapshot.

[NativeStore::accept_validated_coverage](../../crates/araphor-data/src/analysis/native/source/coverage.rs) Data receives a coverage report
  -> [DataWrite::coverage](../../crates/araphor-data/src/analysis/native/source/coverage.rs) Data checks the bound CPU, source epoch, report revision, and exact retry bytes.
  -> [DataWrite::coverage](../../crates/araphor-data/src/analysis/native/source/coverage.rs) Data stages the report, receipt, binding, and history index.
  -> [DataWrite::stage_raw](../../crates/araphor-data/src/analysis/native/source/raw.rs) Data stages changed raw receipt baselines, protected ends, and the allocator floor when raw input is pending.
  -> [DataWrite::commit](../../crates/araphor-data/src/analysis/native/mod.rs) One native batch commits these records and the exact Data cut.
  -> [DataWrite::commit](../../crates/araphor-data/src/analysis/native/mod.rs) Data publishes the matching raw root and native snapshot.

[NativeStore::read_at](../../crates/araphor-data/src/analysis/native/mod.rs) A reader selects global revision R
  -> [NativeStore::cut_view](../../crates/araphor-data/src/analysis/native/mod.rs) Data opens the last metadata cut M at or before R.
  -> [NativeStore::read_at](../../crates/araphor-data/src/analysis/native/mod.rs) The view retains the shared raw root and the immutable bound R.
  -> [DataView::source_receipt](../../crates/araphor-data/src/analysis/native/source/mod.rs) The reader combines the baseline at M with source ranges visible through R.
  -> [RawJournal::freeze_page](../../crates/araphor-data/src/analysis/raw/page.rs) The raw owner validates and freezes the selected ranges under a finite maintenance lease.
  -> [RawPage::read](../../crates/araphor-data/src/analysis/raw/page.rs) The shared page reader returns original records and positions with the existing page limits and cancellation.

[NativeStore::open](../../crates/araphor-data/src/analysis/native/mod.rs) Data reopens the store
  -> [NativeStore::recover_raw](../../crates/araphor-data/src/analysis/native/source/raw.rs) Data checks protected segment ends against decoded entries through the metadata head.
  -> [NativeStore::recover_raw](../../crates/araphor-data/src/analysis/native/source/raw.rs) Data restores receipt baselines and the nonzero allocator floor.
  -> [NativeStore::open](../../crates/araphor-data/src/analysis/native/mod.rs) Data publishes the greater of the recovered raw and metadata revisions.

The native metadata head can be less than the global Data revision. A metadata
write allocates global revision plus one but validates the previous metadata
head. Raw-only input adds no Fjall batch. Historical capture shares the raw
index; it does not rebuild a prefix map. Historical source receipts use visible
ranges and their selected native baseline. They do not clamp the latest cursor.
The captured revision and store identity have read-only accessors.

The source API includes source binding, receipt, status, and exact coverage
reads. The coverage history index supports the existing read contract. The
index is not a subscription change log. Production log-reader routing remains
**Not done**. `AnalysisStore` and `NativeStore` use the same page owner and
finite `RawRead` leases. Captured views contain no raw file handles.

The [native raw cases](../../crates/araphor-data/tests/native_raw.rs) check raw,
metadata, and raw revision order; exact original positions; no native batch for
raw-only input; joint coverage and raw-control publication; historical pending
ranges; exact retries; CPU and epoch conflicts; same-batch coverage bounds;
malformed history records; append and commit failure; compaction; and reopen.
Configured limits, required-input and witness accounting, diagnostics, lifecycle,
retention, backup, and production cutover remain **Not done**. The native owner
supports its current default-limit mode only. No incident gain follows from
this integration.
