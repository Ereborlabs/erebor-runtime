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
The [compiled detector example](../araphor-detector-example/README.md) supplies
the installed component path.

## Build a Wasm component

Enable the SDK `guest` feature. Implement `guest::Guest::package` and
`guest::Guest::evaluate` on the algorithm type. Use
`export_component!(Algorithm)` under `#[cfg(target_arch = "wasm32")]` to export
the generated analysis interface. Use a `cdylib` crate for the core module.
The guest wrapper decodes typed inputs, validates the evaluation, calls
`Guest::evaluate_checked`, and validates and encodes its complete result.
The default method calls `Guest::evaluate`. An algorithm can override the
checked method to use the immutable `CheckedEvaluation` and avoid repeated
input checks. Keep input and output checks on its standalone Rust entry.

The bindings use `wit-bindgen` 0.61.1. The component builder uses
`wit-component` and `wasmparser` 0.258.3. The production host uses Wasmtime
49.0.2. The world imports only the versioned `host.cancelled` operation.
Evaluation time and the seed come from `EvaluationContext`.

Build the [detector example](../araphor-detector-example/README.md) with a fixed
compile-time seed. Use the same Rust compiler, source, target, and lock file
to reproduce the artifact bytes:

```sh
rtk proxy env CARGO_TARGET_DIR=/tmp/araphor-wasm-build CARGO_INCREMENTAL=0 CONST_RANDOM_SEED=araphor-analysis-v1 cargo build --locked --release --target wasm32-unknown-unknown -p araphor-detector-example
rtk proxy env CARGO_TARGET_DIR=/tmp/araphor-wasm-build cargo run --locked -p araphor-detector-example --example build_package -- /tmp/araphor-wasm-build/wasm32-unknown-unknown/release/araphor_detector_example.wasm /tmp/araphor-burst-package
```

`ComponentBuilder::package` writes the SDK declarations and an OCI layout:
`oci-layout`, `index.json`, and content-addressed files in `blobs/sha256/`.
The config contains package metadata; a typed raw layer contains the component.
The builder
removes core debug names and debug sections, keeps the WIT metadata, and
validates the component. One component can implement all declared exports.
The package owner validates the manifest and referenced blobs during admission.
Operators install the built folder or its OCI-layout tar archive. The package
digest is the exact manifest's `sha256:` identity. The package owner compiles
the component in its bounded
compiler process. Installation does not run an author compiler or hook.
`ComponentBuilder::package_component` writes the same folder from an existing
component. It preserves the supplied component bytes.

Host Cargo builds generate the repository components through the
[built-in artifact owner](../araphor-analysis-builtins/README.md#generated-components).
The build machine needs the `wasm32-unknown-unknown` Rust target. CI installs
this target. Generated components stay in Cargo's `OUT_DIR`; do not commit
these files. The author commands above still build the package folder that an
operator installs without an author compiler or installation hook.

`wire` carries uncompressed Arrow IPC streams. It rejects dictionary messages,
compressed batches, unsupported schemas, and row or batch limits before batch
decoding. Supported types are nullable `Null`, Boolean, signed and unsigned
integers, Float32, Float64, Utf8, Binary, UTC nanosecond timestamps,
FixedSizeBinary, List, FixedSizeList, and Struct. Fixed-size lengths are from
1 through 65,536. Schema nesting is at most 16 levels with at most 1,024 fields.
Encoding and decoding copy buffers. The wire bounds apply to encoded bytes
and decoded Arrow storage. They do not claim a zero-copy interface.
Decoding copies each batch into owned Arrow storage. It checks the copy size
before allocation, including temporary validity buffers for nested null data.

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

Each `Model.inputs` entry is an `InputPort` with a `port` and an explicit
`source`. `InputSource::Table(TableRef::Named(name))` selects a named relation.
`InputSource::Table(TableRef::Output(OutputRef))` selects an exact package,
revision, export, and output. `InputSource::Query(query)` selects an admitted SQL
query. A table name is not SQL. A query can read built-in tables and declared
table inputs. There is no separate package dependency list or backend SQL input
map.
`Model::dependencies()` returns the output references with their input ports.
Local references check schema, kind, and revision. Package admission owns
cross-package resolution, cycle rejection, authorization, and scheduling.

`Model::new` accepts `Vec<Port>` and sets `InputMode::Provided`. The constructor
wraps each port with `InputSource::Table(TableRef::Named(port.name.clone()))`.
In `Provided` mode, every source is a table, and the caller supplies every
dataset. Output references still declare retained dependencies. In `Resolved`
mode, every source is a table or query. The query owner resolves each source
for package execution.
Zero-input models also declare their mode. The mode does not depend on an empty
map or a missing SQL key.

For example, change one declared input to a resolved SQL source:

```rust
use araphor_analysis_sdk::{InputMode, InputSource};
let mut resolved = package.exports[0].clone();
resolved.input_mode = InputMode::Resolved;
resolved.inputs[0].source = InputSource::Query("SELECT subject,event_id FROM events".into());
```

Read input schema fields through `model.inputs[index].port`. Output ports remain
`Port` values. Routing metadata does not cross the native or Wasm evaluation ABI;
both sides validate the supplied computation datasets.

## Bounds and graph inputs

`Model.limits` declares maximum batches, rows, data bytes, and checkpoint bytes.
An evaluation can reduce these bounds. It cannot increase them. Input data and
output data have separate budgets. Parameters consume the input budget.
Evidence and reason details consume the output budget. Prior and next state
each have a separate checkpoint budget. These budgets also check dataset names,
revision text, coverage limits, and reference text. Shared Arrow allocations
can be charged more than once. These checks are data bounds, not a hard process
memory limit or execution timeout.
`Evaluation::allocated_bytes` and `Output::allocated_bytes` measure retained
Arrow storage, schemas, and owned metadata for host memory reservations.

Default bounds are 1,024 batches, 1,000,000 rows, 64 MiB of data, and 16 MiB of
checkpoint data. Descriptors, OCI packages, stored package revisions, and package
gRPC messages have no separate aggregate size cap. OCI descriptor sizes and hashes,
frame validation, store usage charges, runtime leases, and model data limits
still apply. Schema checks limit nesting to depth 16 and 1,024 fields per schema. Larger workloads need
explicit bounds and bounded input selection. Client SQL display limits do not
apply to SDK inputs. Tests supply 300 event rows across three batches.

Graph inputs use selected native relations and a typed selection manifest.
The manifest retains every selected version ID, including an empty replacement,
source windows, limits, and traversal boundary state. Graph identities retain
their complete qualified encoding. The SDK requires neither a full
`GraphSnapshotV1` nor an independent graph identity model. The host selects and
authorizes these rows through its existing native storage and traversal owners.
The production `QueryOwner::graph_inputs` API returns these datasets and a held
input reservation. Keep that returned owner alive during evaluation. This API
accepts an authorized host selection; it is not a client authorization endpoint.
The native manifest retains source cursor ranges without inferring UTC time.

## Execution and host boundaries

The WIT declaration carries named Arrow IPC streams and the versioned
evaluation/result envelope. The native C declaration uses Arrow C stream
interfaces in the host process. Both use the same computation port contract.
Syntax tests parse the WIT and compile the C header. The guest feature supplies
the generated component bindings and bounded IPC transport. The package
execution owner supplies cancellation and Wasmtime isolation. Native execution
shares the host process and has cooperative cancellation.

`Package::check_evaluation` returns an immutable `CheckedEvaluation` after it
validates the input contract. `Guest::evaluate_checked` permits one invocation
to reuse that proof. The proof borrows the package and inputs. The native and
Wasm wrappers validate imported data before they create the proof. They
validate output against the same checked contract. Standalone evaluation and
host output validation retain their checks.

Local fixture tests call trusted Rust code in the test process. These tests
do not install a package or prove a sandbox. Structured errors distinguish
invalid, incompatible, unauthorized, incomplete, failed, and limit results.
An invalid computation returns no fixture report.

`araphor-data` retains identity, sensitivity, authorization, evidence, graph,
finding, storage, retry, and commit checks. Its production discovery and HF
detector owners call [shared built-in computations](../araphor-analysis-builtins/README.md)
through installed components built from the SDK contract. The same computation
source runs in local SDK fixtures. Reason conversion retains host validation
and the declared SDK detail schema. Installed detectors retain declared
namespaced reasons and typed details. The host retains the reason mapping used
by historical HF findings.
No package descriptor grants policy or physical authority.

## Current source qualification

The receipt below covers the earlier table and query change. The
[performance simplification record](../../docs/guides/araphor-performance-simplification-review.md)
covers the later checked-input and cached-declaration changes.

The table and query declarations and dataset validators pass 74 SDK cases and
six builder cases. The full current Rust procedure passes: 2,146 tests, zero
failures, and 568 existing ignored cases. It includes the query-owner and
package relation integration cases. Current native qualification passes all 12
selected Data cases and the installed detector E2E case on Linux x86_64 GNU.
The E2E case runs with `PATH` empty. Source and artifact hashes stay unchanged.
The earlier input and cap change at `bf13d846` passes final Rust CI and native
qualification on Linux x86_64 GNU. That result does not qualify this change.
Read the
[verification record](../../docs/plans/araphor-production-dataflow-simplification.md#operation-owned-table-and-query-inputs)
for source hashes, fixture corrections, commands, and remaining work.
