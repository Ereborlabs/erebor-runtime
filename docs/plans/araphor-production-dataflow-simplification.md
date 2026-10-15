# Araphor Production Data Flow Simplification

Remove intermediate representations and execution stages from production Data
paths. This plan follows the request for structural changes. The existing
test preparation changes are qualified. Their complete-suite timing difference
does not establish a production regression or improvement.

## Intended end state

The graph owner passes typed graph data to the existing store owner. Package
storage retains one descriptor and raw executable bytes. A SQL package operation
uses one private SQL engine for its source bindings and model. Authorization,
attribution, lifecycle, recovery, evidence, and physical effect guarantees remain.

These changes add no service, connection pool, compilation cache, or execution
backend. Native and Wasm selection remains based on the package declaration.
Native execution retains its existing process and ABI boundary.

## Scope and decision

The source basis is commit `e31b033ebf95224e8210c73cec5abed4e8149def`.
Commit `9191ddcc` adds its qualification record without changing that source.
The user requests production architecture simplification. The user approves
package storage and one SQL operation. Implement those changes in parallel.
The user approves the revised typed graph handoff, metadata-only header, and
buffered DuckDB appender choice. The user then removes backward compatibility
from scope. The current-format storage decision defines the implemented
format. DataFusion work is not approved.

| Change | Structure removed | Example |
| --- | --- | --- |
| Typed graph commit | JSON as the internal graph handoff; a full generic JSON tree for header extraction | A graph stays typed from derivation to row preparation. Canonical result bytes are produced once. |
| Raw package storage | A descriptor copy and executable code represented as decimal JSON arrays | A 3 MiB executable remains a 3 MiB binary field instead of approximately 6–12 MiB of array text. Metadata is separate. |
| One SQL operation | Separate source and model engines | Three SQL source bindings and one model use one engine instead of four. One Arrow import per source remains. |

The examples describe work removed. They do not state a measured time saving.

## 1. Typed graph commit

### Baseline production flow

[GraphAndFindingOwner::commit_bounded_window](../../crates/araphor-data/src/graph/commit.rs) The graph owner holds a typed snapshot
  -> [graph commit preparation](../../crates/araphor-data/src/graph/commit.rs) serialize the complete snapshot as the result body
  -> [AnalysisStore::commit_graph](../../crates/araphor-data/src/analysis/progress.rs) decode that body into another typed snapshot
  -> [GraphRows::encode_body](../../crates/araphor-data/src/analysis/graph_rows/mod.rs) validate the snapshot and serialize complete canonical JSON again
  -> [GraphHeader::encode](../../crates/araphor-data/src/analysis/graph_rows/header.rs) parse complete JSON into a generic value and remove its rows
  -> [AnalysisStore::commit_progress](../../crates/araphor-data/src/analysis/progress.rs) commit rows, references, usage, and progress in the existing transaction

### Implemented production flow

[CanonicalGraph::new](../../crates/araphor-data/src/analysis/graph_rows/mod.rs) The graph owner validates the typed snapshot and prepares its canonical body once
  -> [GraphAndFindingOwner::commit_bounded_window](../../crates/araphor-data/src/graph/commit.rs) the graph owner checks the body bound before context effects
  -> [AnalysisStore::commit_graph_snapshot](../../crates/araphor-data/src/analysis/progress.rs) the graph owner submits the prepared pair and empty-body commit metadata
  -> [AnalysisStore::commit_graph_inner](../../crates/araphor-data/src/analysis/progress.rs) the store applies shared manifest, witness, scope, and progress validation
  -> [GraphRows::encode_canonical](../../crates/araphor-data/src/analysis/graph_rows/mod.rs) row preparation reuses the existing canonical body
  -> [GraphHeader::encode](../../crates/araphor-data/src/analysis/graph_rows/header.rs) header preparation serializes only required metadata
  -> [GraphRows::insert](../../crates/araphor-data/src/analysis/graph_rows/mod.rs) the transaction appends rows and checks each flush
  -> [AnalysisStore::commit_progress](../../crates/araphor-data/src/analysis/progress.rs) the existing transaction commits references, usage, and progress
  -> [AnalysisResultReceiptV1](../../crates/araphor-data/src/analysis/progress.rs) the graph owner receives the existing receipt

Keep the existing byte-input entry for untrusted input. Require exact current
canonical bytes. Both entries use the same validation and transaction owners.
A typed value does not bypass a boundary. The current format has no layout tape.

```mermaid
sequenceDiagram
    participant Graph as GraphAndFindingOwner
    participant Pair as CanonicalGraph
    participant Store as AnalysisStore
    participant Rows as GraphRows
    Graph->>Pair: Validate snapshot and encode body once
    Graph->>Graph: Check body bound and prepare references
    Graph->>Store: Prepared pair and empty-body commit metadata
    Store->>Store: Existing validation
    Store->>Rows: Prepare header and rows from canonical bytes
    Store->>Rows: Append rows and check each flush
    Store->>Store: Existing commit_progress transaction
    Store-->>Graph: Existing receipt
```

The diagram describes the approved owner boundary. The implemented pair
keeps private snapshot and body fields together. The store supplies commit
body bytes from that pair and rejects independent body bytes at the typed
entry. Header creation builds a metadata-only JSON value. Recursive key order
preserves current metadata encoding. The current header has six fields and
version 2. Graph results remain in the existing
DuckDB transaction. Raw evidence publication remains a separate responsibility.
Do not add a graph journal or a second durable owner.

Prove exact current canonical body, header, row, receipt, and storage-charge
equality between the typed and byte entries. Preserve foreign scope rejection, context
and package references, witness expiry, checkpoint checks, immutable retry,
replacement, quotas, commit synchronization, and revision notifications.
Use the fresh current format. Add no format migration.

Use [native storage tests](../../crates/araphor-data/src/graph/tests/native_storage.rs),
[row encoding tests](../../crates/araphor-data/src/analysis/graph_rows/tests/encoding.rs),
[package reference tests](../../crates/araphor-data/src/analysis/graph_rows/tests/packages.rs),
[graph crash qualification](../../crates/araphor-data/src/graph/tests.rs), and
[backup and corruption tests](../../crates/araphor-data/src/analysis/graph_rows/tests/recovery.rs).
Retain all notice and notification outcomes.

**Done** for source implementation, focused parity, and the final Rust
procedure. The
[graph commit review guide](../guides/araphor-graph-commit-review.md)
records the implemented route and verification evidence.

### Revised choice after binary and DuckDB review

The user requests a comparison with binary formats, Protobuf, and DuckDB.
The [representation review](araphor-graph-binary-duckdb-review.md) contains the
source basis, official API references, tradeoffs, and required proof.

Keep the existing typed SQL columns and CBOR header. Pass the typed snapshot
directly between Rust owners. Serialize only the required metadata for the
header. Use the installed DuckDB appender instead of SQL execution for each
row. Explicitly flush each appender and propagate its error before commit.
Add no Protobuf schema, private DuckDB file codec, or Arrow batch copy.

For example, a graph with 1,000 subjects uses buffered typed appends in the
same transaction instead of 1,000 prepared statement executions. Current
canonical result bytes and selective graph queries remain available. The
complete graph JSON parse and full graph tree used for metadata extraction
are removed.

**Done** for the format comparison and explicit approval of the revised
choice, source implementation, focused qualification, and the final Rust
procedure. No measured runtime saving is established.

## 2. Raw package storage

### Baseline production flow

[PackageBundleV1::from_bytes](../../crates/araphor-data/src/package/bundle.rs) Admission parses and validates external package JSON
  -> [revision preparation](../../crates/araphor-data/src/package/lifecycle/revisions.rs) serialize the whole artifact, including its descriptor and executable byte arrays
  -> [AnalysisStore::install_package](../../crates/araphor-data/src/analysis/packages/revisions.rs) retain descriptor JSON and artifact JSON as separate fields
  -> [AnalysisStore::package_revision](../../crates/araphor-data/src/analysis/packages/read.rs) read those fields
  -> [AnalysisPackageOwner::load_bundle](../../crates/araphor-data/src/package/lifecycle/revisions.rs) parse executable decimal arrays into binary buffers
  -> [bundle validation](../../crates/araphor-data/src/package/admission.rs) validate the reconstructed bundle

### Implemented production flow

The existing external package admission validates V1 bytes
  -> the package owner separates one descriptor, implementation metadata, and raw executable bytes
  -> the store writes the complete immutable revision in one transaction
  -> loading parses one descriptor and the remaining metadata
  -> loading reads binary fields directly into the owned executable buffers
  -> existing bundle validation, authority, and runtime admission remain

Keep the existing package revision row and transaction. The descriptor column
is the only descriptor copy. The artifact column contains a versioned CBOR
envelope with metadata and raw code buffers. Use the installed `minicbor`
dependency. Add one `encoded_bytes` column for the existing logical charge.
Check that this column and the envelope agree. Add no table or code cache.
Recovery derives the canonical byte count from metadata and raw buffers.
Check this count against the row and envelope. There is no migration adjustment.
This field checks consistency. It does not authenticate database contents.

Use the existing DuckDB owner and binary fields. Keep tenant, package ID,
revision, and implementation identity in durable keys. Store native artifacts
as opaque bytes. Native qualification also contains dependency executable
buffers. Store those buffers as binary fields and retain their names, digests,
and order in metadata. The existing native loader owns closure parsing and ABI
validation. Do not add cross-tenant deduplication or a filesystem blob owner.

Package fixtures retain their existing metadata and Arrow IPC payload encoding
in this scope. Those payloads can contain large JSON byte arrays. The remaining
metadata is not guaranteed to be small. This change removes executable arrays;
it does not claim to remove every binary array from package storage.

External V1 package bytes, canonical ordering, digest domains, trust pins,
current SQL semantics, declared backend selection, and native closure bytes
remain unchanged. Canonical serialization and hashing remain at the current
authority boundaries. A stored digest cannot replace hashing untrusted code.

The development store uses schema 21 and the current binary frame. There is
one descriptor copy. Validate current records without repairing malformed
data. Keep current backup, restore, and crash checks. A failed transaction
does not retain a partial revision. Add no older-format conversion or reader.

The external bundle limit remains 32 MiB under the existing encoded rules.
The internal revision limit remains 64 MiB under its existing encoded rules.
Preserve those logical quota units. Smaller physical storage does not increase
the admitted quota. Charge actual owned runtime buffers through existing leases.

Update [schema and usage](../../crates/araphor-data/src/analysis/packages/schema.rs),
[immutable reads](../../crates/araphor-data/src/analysis/packages/read.rs),
[installation](../../crates/araphor-data/src/analysis/packages/revisions.rs),
[recovery](../../crates/araphor-data/src/analysis/packages/recovery.rs), and
[collection](../../crates/araphor-data/src/analysis/packages/collection.rs) together.
Collection removes binary fields only when existing revision retention permits it.

Prove current backup/restore, crash atomicity, descriptor identity,
immutable collisions, dependency closure, changed or missing code rejection,
tenant isolation, quota parity, memory leases, and native/Wasm execution parity.
Preserve candidate-error precedence on retry. Do not change OCI transport or
the external package format as part of this change.

**Done** for explicit architecture approval, implementation, focused
qualification, the final Rust procedure, and execution with current
source-built native artifacts.

The [package storage review guide](../guides/araphor-binary-package-storage-review.md)
records the current source route and verification state.

## 3. One SQL operation

### Baseline production flow

[Package preparation](../../crates/araphor-data/src/package/evaluation/preparation.rs) Preparation requests each SQL source port
  -> [QueryOwner::model_input](../../crates/araphor-data/src/query/model/source.rs) admit and extract the selected source input
  -> [SourceRows::evaluate](../../crates/araphor-data/src/query/model/source/read.rs) open a private source engine and produce an Arrow dataset
  -> [QueryOwner::evaluate_model](../../crates/araphor-data/src/query/model.rs) open another private engine
  -> [ModelExecution::register](../../crates/araphor-data/src/query/model/input.rs) import the Arrow datasets into model relations
  -> [model execution](../../crates/araphor-data/src/query/model/execute.rs) produce output, checkpoint, evidence, and reasons

### Implemented production flow

The package owner selects the declared SQL implementation
  -> the query owner creates one bounded private operation engine
  -> existing source admission and extraction select each input port
  -> each admitted binding produces the existing Arrow input and provenance
  -> schema, bounds, revisions, coverage, and witnesses are recorded
  -> source-only relations are removed before model execution
  -> original model registration imports Arrow inputs once when the model runs
  -> the model reads only admitted ports, parameters, and checkpoint relations
  -> output validation and the existing package commit complete the operation
  -> the operation closes its engine on success, error, or cancellation

Create the shared operation only when the SQL implementation has source
bindings. With no SQL source bindings, use the existing evaluation path. It
opens an engine only when the model must run. The engine lifetime is one
operation. Add no pool or shared mutable connection.
The composed path owns one evaluation reservation across source and model
stages. Do not acquire another reservation through nested standalone APIs.
That nesting can reject the operation when tenant capacity is one. Preserve
the current per-stage deadline semantics when sharing the engine.
Keep standalone public query APIs for their current callers. Native and Wasm
retain their real SDK dataset boundary. Materialize Arrow where the existing
canonical input hash or schema proof requires it. Import each source dataset
once through original model registration when the model runs. Preparation
creates no model input tables. Automatic operations that need no new result
do not import model inputs.
Do not substitute a table ID for a revision hash. This change removes engine
setup; it does not remove every Arrow conversion or memory copy.

Enforce [model relation admission](../../crates/araphor-data/src/query/model/schema.rs)
and parser guards. A private schema name is not an access boundary. A model
must not read source-only relations, the database catalog, or an unadmitted
port. Test hidden-source access and name collisions before switching callers.

Retain input leases through computation and commit preparation. Charge source
projections, port relations, intermediate results, and output. Preserve row,
scan, input, output, checkpoint, and aggregate bounds. Preserve extraction and
evaluation deadlines, cancellation, source checks, activation, and authority
checks. A failed port must not execute the model or commit partial state.

Prove exact input revisions, output, request, checkpoint, evidence, reasons,
dependency results, retry, rollback, and budget behavior. Use existing SQL
package lifecycle and query model tests. No durable format change is intended.
If retained bytes change, stop and define the result contract before implementation.

**Done** for explicit architecture approval, implementation, focused parity,
source visibility proof, and the final Rust procedure.

The [SQL operation review guide](../guides/araphor-sql-operation-review.md)
records the current source route and verification state.

## Current-format storage decision

The user directs this work to remove legacy support. Backward compatibility is
not required. This instruction replaces the earlier migration and legacy
layout requirements. The implemented flows above apply this instruction.

Use a fresh development store and the current backup manifest. There are no
deployed older stores. Remove old-schema migration code, migration-only
fixtures, and old-version rejection matrices. Keep current-format backup,
restore, corruption, retention, quota, and crash checks.

Store canonical graph results. Remove noncanonical layout recording and replay.
The byte-input boundary still validates its snapshot and requires canonical
bytes. Remove the layout column and redundant source-byte count. Keep the
current canonical result format, native rows, typed pair, references, and
transaction. Do not retain an old header decoder.

Store current binary package records. Remove legacy JSON conversion and the
signed migration adjustment. Validate the current canonical encoding count
against both the frame and the row. The current external package V1 format,
identity, dependency bytes, native ABI, and 32/64 MiB limits remain supported.

Keep the existing current-format integrity guards. Add no older-data
conversion, preservation, or rejection-specific bookkeeping.

**Done** for explicit removal of backward compatibility and source cleanup.
**Done** for focused current-format qualification and the final Rust procedure.

## Execution and verification

Implement and commit each approved structural change separately. Run focused
functional cases before the final repository procedure. Follow
[verification.md](../../.agents/verification.md) after the last covered edit.
Use ordinary Rust tests and existing qualification entry points.

No new performance test is approved by this document. Before adding a runtime
comparison, obtain explicit approval for its workload, runtime, and pass/fail
limits. Record source, binary, profile, host load, stage counts, bytes, and
terminal results. Functional parity is required before timing qualification.

The source changes are committed separately:

| Commit | Change |
| --- | --- |
| `6b6d5ebb` | Raw package executable storage and current-only recovery |
| `efac8911` | One private SQL engine per package operation |
| `78f80579` | Typed graph commit and buffered DuckDB row appends |
| `9b3cbab8` | Preserve the existing finding read budgets |
| `9f1f4ffa` | Derive snapshot test capacity from raw fixture bytes |
| `cffde410` | Qualify canonical graph input through query reads |

Focused qualification covers 71 distinct Data cases and 66 SDK cases. The
first Data run passes 70 cases. Its sole failed SQL parity assertion is
corrected, and that exact case passes on retry. The original source head is
`78f805794f49d22b12e72c3fa8e65f406157bb47`.

The first final Rust procedure on that source passes formatting, workspace
checking, and clippy. Data reports 616 passed, 3 failed, and 19 ignored. The
procedure stops at Data. Read
`/tmp/araphor-production-final-ci-attempt1-source.json` and
`/tmp/araphor-production-final-ci-attempt1.log` for this result.

The large-context graph case also fails in isolation with
`AnalysisReadDeadline`. Its record is
`/tmp/araphor-production-failures-original.json`. The current format bound
had also reduced the finding cache and query batch budgets. Restore their
existing 32 MiB budget independently of the 16 MiB result bound. Add a small
two-header retention check. Correct the snapshot test capacity for tightly
allocated raw executable buffers. Require canonical bytes in the graph query
fixture. These corrections do not add compatibility behavior or change the
read deadline.

The seven targeted correction cases pass. These cases cover the three failed
tests and all four finding-read tests. Formatting and focused clippy pass.
The source hashes remain unchanged during the targeted run. Read
`/tmp/araphor-production-targeted-fixes.json` and
`/tmp/araphor-production-targeted-fixes-tests.log` for this result.

The final source head is `cffde41073aa29380869de83b0ca18b078151d4f`.
The second final Rust procedure passes on that committed source. The final
record is `/tmp/araphor-production-final-ci-source.json`, and the log is
`/tmp/araphor-production-final-ci.log`.

The final command is `bash .github/scripts/verify-rust-ci.sh`, with
`CARGO_BUILD_JOBS=1` and `RUST_TEST_THREADS=4`. All 90 outer harnesses finish.
The result is 2,121 passed, 0 failed, and 568 existing ignored tests. Data has
620 passed, 0 failed, and 19 existing ignored tests. The source hashes remain
unchanged. The result summary is `/tmp/araphor-production-final-ci-report.json`.

| Functional run | Result | Observed time |
| --- | --- | --- |
| Workspace check | Pass | 14.48 s |
| Workspace clippy | Pass | 66 s |
| Data | 620 passed, 19 ignored | 889.53 s |
| Control | 188 passed, 2 ignored | 106.65 s |
| Mithril E2E | 191 passed, 528 ignored | 488.20 s |
| Node library | 282 passed, 1 ignored | 7.46 s |
| Complete final procedure | Exit 0 | 1,666.48 s |

These are ordinary functional-run times. They do not establish a speed
improvement. Source-built native artifact cases are not part of the default
CI result. The additional current-artifact qualification passes on the same
Data binary.

The existing author builder compiles six Rust native libraries from the current
source in 30.79 seconds. The build uses the locked release profile, one Cargo
job, and the existing `target/analysis-native` cache. The output is
`/tmp/araphor-production-native-current`. The retained earlier artifact
directory is unchanged.

With `ARAPHOR_NATIVE_DIR` set to this current output, 12 existing cases pass,
with 0 failed and 0 ignored, in 255.98 seconds. Eight package cases execute
stored native binaries through installation, checkpoint recovery, overflow,
error, capacity, cancellation, grant expiry, backend selection, and host-fault
restart paths. Two Discovery cases and two graph cases prove native/Wasm
algorithm parity and large-input behavior. The platform is Linux x86_64 GNU
with glibc 2.39. The source hashes remain unchanged.

Read `/tmp/araphor-production-native-qualification.json`,
`/tmp/araphor-production-native-qualification-build.log`, and
`/tmp/araphor-production-native-qualification-tests.log` for the command,
artifact hashes, source hashes, and terminal results. Nested restart helper
output does not add to the 12 parent cases. This is functional qualification,
not a controlled speed benchmark.

**Done** for source analysis, explicit approval, implementation, separate
source commits, focused qualification, the final Rust procedure, and
current-artifact native execution qualification. No approved implementation
work remains. Runtime savings remain unmeasured. DataFusion work is not part
of this implementation.
