# Araphor Analysis SDK

Define a portable algorithm interface once. Use the same `Package` value for
inspection, interface declarations, and local Rust fixture validation. The SDK
does not depend on Control, DuckDB, or durable storage.

## Author an export

The [files.count example](examples/files_count.rs) defines an `events` input and
a `counts` output. Each event has a required subject and an unsigned event ID.
The computation counts distinct event IDs per subject. Each output row refers
to its input rows. Three distinct events for `subject.1` produce count `3`.

```rust
use araphor_analysis_sdk::{DataType, Field, Model, Package, Port, Schema};

let events = Schema::new(vec![
    Field::new("subject", DataType::Utf8, false),
    Field::new("event_id", DataType::UInt64, false),
]);
let counts = Schema::new(vec![
    Field::new("subject", DataType::Utf8, false),
    Field::new("count", DataType::UInt64, false),
]);
let mut output = Port::new("counts", counts);
output.evidence_required = true;
let package = Package::new("files", "1", vec![Model::new(
    "files.count", vec![Port::new("events", events)], vec![output],
)]);
package.validate()?;
# Ok::<(), araphor_analysis_sdk::Error>(())
```

Define the algorithm as an ordinary Rust function with this signature:
`fn(&Evaluation) -> Result<Output>`. Call `package.test(&fixture, algorithm)`.
The fixture supplies exact named input revisions, coverage, parameters, time,
seed, limits, and any prior checkpoint. The SDK validates inputs before the
function runs. The SDK validates the complete output before it returns a
`FixtureReport`. Assert expected computation results in the Rust test.

Use `package.inspect()` to get the descriptor JSON. Inspection reads metadata;
it does not call an algorithm. Agent clients use this same descriptor.
Use `package.build(directory)` to write `descriptor.json`, `analysis.wit`, and
`analysis.h`. This operation generates declarations. It does not compile an
executable. A write failure can leave declaration files in the author directory;
repeat the build to replace those files.

Run the complete example from the repository root:

```sh
cargo run -p araphor-analysis-sdk --example files_count -- /tmp/araphor-files-count
cargo test -p araphor-analysis-sdk --all-targets
```

The example uses fixture subject IDs. Production subject identities and proof
qualification remain with the host.

## Develop a detector

The [sensitive access example](examples/sensitive_access.rs) compares observed
subject/resource pairs with an exact audited baseline. It returns each access
outside that baseline as a `Findings` row, with a typed
`sensitive-access.OUTSIDE_BASELINE` reason and evidence for the observed event.
The result retains the baseline revision. An empty baseline retains its revision.
A gapped baseline, an unknown baseline, or a selection limit returns
`Incomplete` because the detector cannot establish complete membership.

Use `evaluation.input("baseline")?` to select a named input. Use Arrow's
`RecordBatch::column_by_name` and typed casts to read columns. Use the declared
schemas to make output and reason batches. Arrow batch errors convert into the
SDK error without a separate error mapping. Test the detector with
`package.test(&fixture, SensitiveAccess::evaluate)`.

```sh
cargo run -p araphor-analysis-sdk --example sensitive_access
```

This example uses local fixtures. It reports a difference from an audited
baseline. It does not establish malicious intent, grant policy authority, or
prevent an operation. Zero findings means that the supplied events contain no
match. Check the input coverage in the report before you assess that result.
Installation and target execution remain later work.

## Data and result rules

Each named dataset contains ordered Arrow `RecordBatch` values. Every declared
dataset must be present exactly once. An empty dataset can have no batches.
Named outputs can have different row counts. Batch schemas must equal the
declared schema, including field nullability and metadata.

Use Arrow integer types to preserve integer values exactly. Timestamps use
signed 64-bit nanoseconds with the `UTC` timezone. An absent field is a schema
error. A nullable field can contain null. If an algorithm distinguishes a
missing source value from an explicit null, declare a separate presence field.
Lists, fixed-size lists, and structs represent repeated or nested data. Binary
fields require a declared payload type or encoding when their meaning is not
raw bytes. Declare such information in Arrow field metadata.
Use the same metadata for field descriptions and units in inspection output.
`SourceWindow` records inclusive UTC start and end bounds and the exact source
identity bytes. The host supplies that selection. A record without source time
must declare the missing time; the SDK does not generate an event timestamp.

Selected, non-null floating-point values must be finite. Validation applies
list offsets and parent null masks before it checks nested values. Arrow
buffer validation and memory bounds still apply to retained backing storage.
The `Null` type requires a nullable field, including inside nested types.
Integer and timestamp comparisons are
exact. `NumericTolerance` declares nonnegative absolute and relative bounds
for later comparison across targets. The comparison rule is
`abs(a - b) <= max(absolute, relative * max(abs(a), abs(b)))`.
The current fixture runner validates the bounds; the author test performs the
comparison. A tolerance does not permit invalid values or change algorithm
thresholds.

Input row order is the batch order, then the row order inside each batch.
`RowRef.row` is the global zero-based ordinal across those batches.
`EvidenceLink` connects an output row to a named input row. Required evidence
applies to every output row in that port. Duplicate links, unknown datasets,
and out-of-range ordinals fail validation. A checkpoint row cannot supply
evidence. Supply retained prior results as named inputs, or replay retained
raw input, when a stateful computation needs earlier evidence.

The author defines stable output ordering and tie rules in the algorithm.
The SDK preserves the returned order. Exact input revisions, host time, and a
declared seed allow replay. The SDK does not give an algorithm a live clock,
database, network, or authority callback.

A reason uses a declared `package_id.local_code` and one row of typed details.
The reason refers to an existing output row. State uses named typed datasets
under a nonzero checkpoint version. An initial evaluation can omit state.
A stateful export must return its next checkpoint. A wrong version, schema,
or dataset rejects the complete evaluation.

`Dependency` binds one model input to an exact package revision and named
export/output. Local bindings check the output schema. Dependency resolution,
cycle rejection, authorization, and scheduling belong to package admission.
The SDK does not load or execute a dependency.

## Bounds and graph inputs

`Model.limits` declares maximum batches, rows, data bytes, and checkpoint bytes.
An evaluation can reduce these bounds. It cannot increase them. Input data and
output data have separate budgets. Parameters consume the input budget.
Evidence and reason details consume the output budget. Prior and next state
each have a separate checkpoint budget. These budgets also check dataset names,
revision text, coverage limits, and reference text. Shared Arrow allocations
can be charged more than once. These checks are data bounds, not a hard process
memory limit or execution timeout.

Default bounds are 1,024 batches, 1,000,000 rows, 64 MiB of data, and 16 MiB of
checkpoint data. Descriptors have a 1 MiB encoded size bound. Schema checks
limit nesting to depth 16 and 1,024 fields per schema. Larger workloads need
explicit bounds and bounded input selection. Client SQL display limits do not
apply to SDK inputs. Tests supply 300 event rows across three batches.

Graph inputs use selected native relations and a typed selection manifest.
The manifest retains every selected version ID, including an empty replacement,
source windows, limits, and traversal boundary state. Graph identities retain
their complete qualified encoding. The SDK requires neither a full
`GraphSnapshotV1` nor an independent graph identity model. The host selects and
authorizes these rows through its existing native storage and traversal owners.

## Execution and host boundaries

The WIT declaration carries named Arrow IPC streams and the versioned
evaluation/result envelope. The native C declaration uses Arrow C stream
interfaces inside one isolated worker. Both carry the same descriptor.
Syntax tests parse the WIT and compile the C header. Runtime transport,
cancellation, isolation, executable builds, and target parity are later work.

Local fixture tests call trusted Rust code in the test process. These tests
do not install a package or prove a sandbox. Structured errors distinguish
invalid, incompatible, unauthorized, incomplete, failed, and limit results.
An invalid computation returns no fixture report.

`araphor-data` retains identity, sensitivity, authorization, evidence, graph,
finding, storage, retry, and commit checks. Current HF package descriptors use
the SDK validator. Reason conversion retains host validation and the declared
SDK detail schema. Current detector dispatch
and its fixed reason catalogue remain operational. General installed-package
result mapping must support new namespaced reasons before detector activation.
No package descriptor grants policy or physical authority.
