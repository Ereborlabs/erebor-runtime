# Native execution performance handoff

Work stopped at the user's request on 2026-11-03. The performance target
is **Not done**. The latest complete invocation fails. Do not report the
current source as stable or the workload as qualified.

## Test and target

Run only this existing Rust test:

```text
discovery::packages::required::incident::incremental::follows_incremental_sources
```

Owner: [incremental.rs](../../crates/mithril-e2e/src/discovery/packages/required/incident/incremental.rs).
The workload has four sources, 4,096 initial events per source, and eight
later events: 16,392 events in total. Preserve the workload, all assertions,
15-second RPC gate, 90-second progress gate, and debug profile. The case
checks real WAL intake, authenticated Control, central journal data, native
Query subscriptions, package execution, Graph and finding changes,
notification subscriptions, ordering, isolation, and incremental work.
The notification check proves availability through a subscription. It does
not separately prove delivery to an external sink.

The required path is:

```text
Event arrives
  -> Data commits the central journal
  -> Query wakes the existing subscription
  -> the saved DataFusion plan executes
  -> the plan calls the package
  -> Data commits Graph/finding changes and progress atomically
  -> a notification subscription receives the finding
```

Use the native DataFusion SQL parser, logical planner, optimizer, physical
planner, and execution. Use table providers for tables. Keep package calls
inside the physical pipeline. Compute and store changes incrementally.
The user requires at least a 100-times speed improvement and an event path
in milliseconds. Neither result has been proved.

## Current source

- Query retains the complete prepared native executable. New invocations
  receive a fresh task context. The two large planning passes after event
  arrival are removed.
- Native journal positions drive change detection. Per-call source points
  use call ID, publication revision, journal position, and context revision.
  Empty progress receipts preserve calls that did not run. Twenty-one
  continuing commits in the preceding run report `reset=false`.
- Query retains indexed Arrow blocks in RAM. The existing `RetainedCall`
  also holds last-call input/output Arrow references in RAM. This is not
  a durable input/output archive. Durable call records hold references,
  metadata, and optional package checkpoints. Graph changes are durable.
- Source and replay database operations have separate interrupt controls.
  Native task tracing preserves the invoking dispatcher and span.
- Source-header and notification readers use native Arrow columns. They
  do not deserialize intermediate row lists.
- DataFusion is 55.0. Arrow is 59.2. The vendored native physical optimizer
  contains the recorded upstream statistics correction. The DuckDB native
  library is unchanged. See the latency plan for the migration history.
- The current private Graph control SQL uses native aggregates and
  `UNNEST`. It uses no lambda, private dialect, or custom parser. Source
  review passes; the latest bulk run still panics.

Reading route:

1. [Prepared execution](../../crates/araphor-query/src/definition.rs).
2. [Subscription runtime](../../crates/araphor-query/src/stream/physical/runtime.rs).
3. [Source index](../../crates/araphor-query/src/sources/index.rs) and
   [Before capture](../../crates/araphor-query/src/sources/rows/before.rs).
4. [Package execution and receipt](../../crates/araphor-query/src/definition/physical.rs).
5. [Analysis publication](../../crates/araphor-analysis/src/instance/sink.rs).
6. [Managed Data commit](../../crates/araphor-data/src/analysis/managed/commit.rs).
7. [Graph publication](../../crates/araphor-data/src/analysis/graph_rows/publication.rs)
   and [Graph contributions](../../crates/araphor-graph/src/contributions.rs).
8. [Current control SQL](../../crates/mithril-control/src/service/packages/graph-control.sql).

## Latest measured state

The last focused build passes in **191.591930 s**. The last live process
fails in **347.853963 s**, exit 101. Its log is
`/tmp/araphor-live-native-control-aggregate-20261103.log`.

| Completed boundary | Previous run | Latest run |
| --- | ---: | ---: |
| Configuration | 55.198427 s | 47.286763 s |
| Native physical planning, inside configuration | 44.984633 s | 37.528233 s |
| Listening | 0.084568 s | 0.086028 s |
| Subscription setup | 0.061748 s | 0.061942 s |
| Policy setup | 0.241958 s | 0.229682 s |
| Inclusive startup | 55.601662 s | 47.681283 s |
| Initial notification, source 33 | 17.283643 s | 15.768149 s |
| Initial notification, source 34 | 18.495476 s | 16.780978 s |
| Initial notification, source 35 | 19.622795 s | 17.868428 s |
| Initial notification, source 36 | 20.996588 s | 19.717617 s |
| External process, failed | 284.597287 s | 347.853963 s |

The latest first-source execution records 5,045 reads and 4,908 rows,
against 9,275 reads and 7,728 rows before the SQL correction. These are
native Arrow/source reads. They are not counts of DuckDB queries.
The four initial source checks pass. The eight later arrivals do not run.
Startup includes its setup sections. Planning is inside configuration.
Concurrent or nested internal spans must not be added as wall time.
Both whole runs fail at different boundaries. Their totals do not prove
a completed-workload speed factor.

The current failure is an Arrow panic during the first bulk work:

```text
arrow-array-59.2.0/src/record_batch.rs:857
Cannot convert nullable StructArray to RecordBatch
left: 1
right: 0
```

The first panic is at 14:20:52 UTC. The final error contains the resulting
`JoinError::Panic` at `araphor-analysis/src/instance/host.rs:395`. The case
continues to accept journal data, then fails during shutdown at 14:24:34.
The final elapsed time therefore includes waits after the background
panic. No Rust backtrace was enabled. The exact caller of the invalid
conversion is **not isolated**. Do not label this run as an RPC timeout.
The preceding 284.597287-second run did fail at a bulk-upload RPC timeout.

Before the SQL change, the first Graph conversion took 13.356 ms. Its
managed write spent 2.925956 s in transaction work and 45.938 ms in metadata
commit. Notification work processing took 2.674356 s. Under bulk input,
writer acquisition reached 12.360090 s. That accessor also performs catalog
preparation and capacity checks; it is not pure lock wait. Raw intake uses
the same writer owner. Current timers use `writer_acquire_s`; older logs
use `writer_wait_s` for that same accessor interval.

The latest Port timings show 312 Graph capture callbacks in the first cut.
Their median awaited callback duration is about 50.5 ms. Those callbacks
read a bounded in-memory header but pass through blocking task dispatch.
There are 661 total Port completions in that cut, including nested calls.
Do not sum those inclusive spans or call those values CPU time.

## Pending changes and next work

1. Isolate and fix the nullable-Struct panic in the current production path.
   A new invocation can enable a Rust backtrace. Keep the same live case.
   Preserve source identity, null handling, row order, and input provenance.
2. Complete the entire unchanged case, including eight later arrivals,
   before claiming incremental runtime qualification.
3. A grouped Graph staging draft has final source approval. It is saved as
   [graph-grouped-staging.patch.gz](araphor-execution-handoff/graph-grouped-staging.patch.gz).
   It is **not applied, built, or run**. It shares canonical record,
   position, and fully checked context preparation. Three detector scopes
   use one native contribution stage. Metadata keeps its existing later
   publication boundary. This preserves unchanged-result and compare-and-
   swap behavior. Decompress the artifact and check the patch against the committed source
   before applying it. Build and run only the same live case. Measure its effect.
4. The next proposed input change inlines only the bounded pure Graph
   Capture and Window callbacks in their existing async owner. Preserve
   source/context/control/permit checks and memory leases. Keep real
   database and heavy work on their existing blocking paths. This proposal
   has no final implementation or runtime approval. Do not assume it is
   already applied. No new cache, parser, executor, or source identity is
   needed for that proposal.
5. Use measured costs for later work. Data currently stages Graph work even
   when detector membership changes are empty. `GraphRows::unchanged`
   also considers cursor, coverage, package, and deadline metadata. Do not
   remove those checks without replacing their ownership and recovery
   guarantees. This is a candidate for redesign, not an implemented fix.

All six latency proposals and further coherent native rewrites are approved
when they improve performance. Each implementation still needs a concrete
owner/data-flow proposal and review for simplicity, native reuse, and
preserved guards. A source approval is not a passing runtime result.

## Commands and evidence

Use `rtk` for shell commands. Only the named case is authorized during this
performance work. Do not run full workspace CI or a different test matrix.

```sh
rtk proxy env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=6 cargo test -p mithril-e2e --lib   discovery::packages::required::incident::incremental::follows_incremental_sources   --no-run --message-format=short
```

The linked [runner](araphor-execution-handoff/run-live.py) records external
elapsed seconds, exit status, the exact case, and process ID. Its build
mode currently uses `/tmp/araphor-native55-duckdb-override.toml`. A saved
[override](araphor-execution-handoff/duckdb-cache.toml) points to the existing
unchanged native DuckDB archive. Use it only while that exact archive,
headers, and bindings exist. A normal Cargo build remains the fallback.
Do not delete the archive to clean old build output.

```sh
rtk proxy env RUST_BACKTRACE=1 RUST_LOG=info,mithril_e2e=debug,araphor_query=debug,araphor_analysis=debug,araphor_data=debug   target/debug/deps/mithril_e2e-a9e3c78154ebcf6e   discovery::packages::required::incident::incremental::follows_incremental_sources   --exact --nocapture --test-threads=1
```

The executable name can change after a dependency or target change. Use the
executable from the focused build. The saved
[timing evidence](araphor-execution-handoff/timing-evidence.txt) records the
last runs and actual owner spans. Raw logs remain under `/tmp`. The
[summarizer](araphor-execution-handoff/summarize-live.py) and
[boundary reader](araphor-execution-handoff/summarize-boundaries.py) read
those logs; they do not replace the Rust test.

Current documents:

- [Latency plan](araphor-reactive-execution-latency.md): approvals, six
  proposals, source history, timing history, and unfinished results.
- [Implementation review guide](../guides/araphor-retained-execution-review.md):
  actual owners, source links, retention, control, and receipt checks.

## Prohibited shortcuts

- No time-based polling. Timer wakes may represent actual query-window or
  expiry boundaries. Source changes use journal positions and subscriptions.
- No hashing for identity or change detection. Do not add repeated hashing
  or serialization to this path. Keep native Arrow values as Arrow.
- No durable copies of package inputs, output batches, selected relations,
  or source captures. Use central-journal references. Materialized Graph
  changes and explicit package checkpoints retain their approved owners.
- No private parser, dialect, planner, cache, or executor to replace a
  feature that DataFusion or an existing crate provides.
- No arbitrary caps or default quotas. Do not add a scan budget or revive
  stored-package or OCI package limits.
- No contract-version bumps or backward-compatibility layers during this
  development work.
- Do not weaken assertions, change the workload, extend timeouts, change
  the debug profile, or substitute a different benchmark.
- Do not claim 100 times from a failed, interrupted, or partial run.
- Do not discard source or replace a crate before its behavior has a
  checked replacement. Preserve unrelated user files and external trees.

The user stopped the implementation. No agents or test runs remain active.
The paused editor process was resumed. No new feature work was performed
for this handoff. The grouped staging draft remains a review artifact.
