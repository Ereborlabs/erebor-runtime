# Native execution performance handoff

## Desired state

The required event path is:

```text
Event arrives
  -> Data commits the central journal
  -> Query wakes the existing subscription
  -> the saved DataFusion plan executes
  -> the plan calls the package
  -> Data commits Graph/finding changes and progress atomically
  -> a notification subscription receives the finding
```

SQL uses the native DataFusion parser, logical planner, optimizer,
physical planner, and execution. Use existing DataFusion and dependency
features where they provide the required behavior. The design must be
simple and coherent. Computation and storage must be incremental.
The event path must run in milliseconds. The user requires at least a
100-times performance improvement. This target is not achieved.

Query owns subscriptions, windows, plans, and result streams. Analysis
owns job start, stop, and recovery. The package runtime executes the
selected implementation with Arrow inputs. Data owns the central journal,
durable results, progress, and atomic commits. Graph owns node, edge,
and finding changes inside Data's transaction.

The user requires central-journal references instead of durable copies of
package inputs, output batches, selected relations, or source captures.
Graph changes and the explicit package saved-state contract retain their
approved purposes. Change detection uses journal positions. No polling,
hashing for identity or change detection, unnecessary serialization,
arbitrary limits, or default-enabled quotas are allowed. Do not replace
native DataFusion features with custom implementations. Do not weaken the
test, extend timeouts, change the workload or profile, or substitute a
different test to claim the performance result.

## Current state

Implementation stopped at the user's request on 2026-11-03. The source
snapshot is commit `ae421299e`. The product is not qualified as stable.
No complete passing run of the live workload is recorded.

The test is:

```text
discovery::packages::required::incident::incremental::follows_incremental_sources
```

Source: [incremental.rs](../../crates/mithril-e2e/src/discovery/packages/required/incident/incremental.rs).
The workload has four sources, 4,096 initial events per source, and eight
later arrivals: 16,392 events in total. Its RPC gate is 15 seconds. Its
progress gate is 90 seconds. Runs use the debug profile. Only this live
case was run during the current iterations.

The current source retains a prepared native DataFusion executable and
creates a fresh task context for each invocation. Query retains indexed
Arrow blocks in RAM. The current `RetainedCall` also holds last-call
input/output Arrow references in RAM. This describes existing code; it
is not a requirement to keep that cache. Durable call records hold
references, metadata, and optional package checkpoints. Graph changes
are stored durably.

Per-call source points contain a call ID, publication revision, journal
position, and context revision. In the preceding run, 21 continuing call
commits reported `reset=false`. The latest run does not complete the
later-arrival checks. Full incremental behavior is not qualified.

Source and replay database operations use separate interrupt controls.
Native task tracing carries the invoking dispatcher and span. The changed
source-header and notification readers use Arrow columns instead of
intermediate row deserialization. The source uses DataFusion 55.0 and
Arrow 59.2. The recorded large planning passes after event arrival are
absent from these runs.

The last focused build passes in **191.591930 seconds**. The latest live
process fails after **347.853963 seconds**, exit 101. Its log is
`/tmp/araphor-live-native-control-aggregate-20261103.log`.

| Completed boundary | Preceding run | Latest run |
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

The four initial source checks pass in the latest run. The eight later
arrivals do not run. Startup includes its setup sections. Configuration
includes physical planning. Both whole runs fail at different boundaries.
Their total durations do not prove a completed-workload speed factor.
No passing completed-workload baseline is established by these runs.

The latest first-source execution records 5,045 native source reads and
4,908 rows. The preceding run records 9,275 reads and 7,728 rows. These
counts include native Arrow reads; they are not DuckDB query counts.

In the preceding run, the first Graph conversion takes 13.356 ms. Its
managed write spends 2.925956 s in transaction work and 45.938 ms in
metadata commit. Notification work processing takes 2.674356 s. Under
bulk input, writer acquisition reaches 12.360090 s. That accessor also
performs catalog preparation and capacity checks. Its timing does not
isolate lock wait. Transaction work does not isolate DuckDB execution
from Rust validation and other work. Nested and concurrent timings must
not be added as wall time.

## Failures

The latest run panics during the first bulk work:

```text
arrow-array-59.2.0/src/record_batch.rs:857
Cannot convert nullable StructArray to RecordBatch
left: 1
right: 0
```

The first panic occurs at 14:20:52 UTC. The final error contains the
resulting `JoinError::Panic` at
`crates/araphor-analysis/src/instance/host.rs:395`. Journal data continues
to arrive after the background panic. The process fails at 14:24:34 UTC.
The total duration includes waits after the panic. No Rust backtrace was
enabled. The exact conversion caller and root cause are not isolated.

The preceding run fails after **284.597287 seconds** with:

```text
Control unary RPC timed out
```

That failure occurs during bulk upload. Its Analysis cancellation
messages occur during shutdown. No read-control collision is observed
before shutdown in that run.

An earlier control-query draft fails during logical admission after
**3.980711 seconds**. It reports `SchemaError::FieldNotFound` for lambda
variable `h`. The current query uses native aggregates and `UNNEST`
instead. The latest run passes admission but still has the bulk panic
stated above.

The performance target, complete workload, later-arrival behavior, and
restart behavior remain unqualified. No verified next implementation or
performance remedy was established.
