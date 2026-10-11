# Installable Algorithms And Detectors

Evaluate how an author can add a computation and a detector that uses it without
changes to Araphor source. Existing bpftrace collection is the input baseline.

Result: **Research: Done. Direction: Approved for the plan. Implementation: Not done.**
Research date: 2026-10-09. Parent: [Control, discovery, and detection](README.md).
The [7.5 child phases](phase-7-5-graphs-findings-and-notifications/README.md#approved-extension-and-child-phases)
record the selected SDK and execution direction. They supersede the earlier
native-first and mandatory Python-to-Wasm choices. This evaluation retains the
comparisons and examples; the child plans own implementation scope. The
[security package design](extensible-security-packages-design.md) retains its
evidence and authority rules.

Current Araphor algorithms move to the SDK contract in the 7.5.2 follow-up.
Existing production owners call the shared Rust computation directly and must
produce equivalent results. Phase 7.5.4 runs that same computation as installed
Wasm packages and replaces the built-in dispatch after runtime checks pass.
Full upstream algorithm development belongs to 7.5.8 for Discovery Engine and
7.5.9 for Security Analytics. The [source inventory](phase-7-5-graphs-findings-and-notifications/algorithm-coverage.md)
defines their pinned scope and completion rules. The examples below are not a
complete upstream algorithm catalogue or proof of compatibility.

## Intended end state

An operator installs one file or package. Araphor identifies its computations,
checks their inputs, and runs eligible detectors under the installation grant.
The operator does not install Python, resolve dependencies, or run another
service. An agent can inspect the same inputs, parameters, tests, and results.

**Selected direction:** use one analysis SDK and package contract. A named model
consumes typed datasets and returns typed datasets, evidence, and next state.
Rust is the first SDK. Wasm components under Wasmtime are the default compiled
target; existing DuckDB evaluation remains the SQL path. Qualified native
workers support frequently used algorithms and native dependencies. Python is
optional and uses a bundled worker when selected. Compiled packages need no Python.

The SDK generates descriptors and target bindings. Host owners retain permission,
resource, result, and commit checks. A package can carry Wasm and native artifacts
for the same export. Require output and state parity before switching targets,
and record the selected artifact. No target has a measured speed advantage yet.

## Runtime flow

```text
Operator installs a file or a package
  -> admission records one immutable revision and its locked dependencies
  -> admission checks declared exports against their implementation interfaces
  -> admission checks executable interfaces without loading package code into Control
  -> admission validates schemas, dependency bindings, scope, and runtime limits
  -> the analysis catalogue records the admitted models

An input revision or recorded evaluation time changes
  -> the analysis owner selects authorized input revisions and prior state
  -> extraction closes durable readers before evaluation
  -> the scheduler evaluates model dependencies in order
  -> the admitted SQL, Wasm, native, or Python implementation evaluates the model
  -> the result owner validates output, attribution, and evidence references
  -> AnalysisStore commits output, next state, progress, and quota together

Evaluation fails, exceeds a limit, or loses its grant
  -> the owner cancels the evaluation and discards uncommitted output
  -> the supervisor terminates the worker if cancellation does not complete
  -> the owner preserves the last committed state and records incomplete coverage

An evaluation is retried
  -> an identical committed operation returns its original receipt
  -> changed input under the same operation key is rejected

Operator updates a package
  -> admission validates the new exports and dependency closure
  -> the owner prepares state conversion or a retained-input rebuild
  -> a successful commit activates the replacement analysis revision
  -> failed preparation preserves the previous revision
```

## Evidence from existing systems

The following are product or source facts. The design judgments are specific to
Araphor's existing Rust owners, SQL evaluator, and retained evidence.

| System | What the author installs or writes | Useful part | Limit for this task |
| --- | --- | --- | --- |
| [SQLMesh Python models](https://github.com/SQLMesh/sqlmesh/blob/main/docs/concepts/models/python_models.md) | A Python file with a model function, output schema, and upstream model references. SQL models share the model system. | A general algorithm can produce a dataset that another model consumes. | Its warehouse lifecycle does not supply Araphor's evidence validation or atomic finding/state commit. Borrow the model interface; keep existing durable owners. |
| [Apache Hamilton](https://hamilton.apache.org/concepts/node/) | Python modules with typed functions. Parameter names identify dependencies. | Functions, dependencies, and documentation remain close to the code. Helpers remain ordinary functions. | A Python dataflow is not an authorization or recovery boundary. Do not infer permission from a dependency or type annotation. |
| [Panther Python rules](https://docs.panther.com/detections/rules/python) and [shared helpers](https://docs.panther.com/detections/rules/python/globals) | Python rule functions and importable helper modules. | Familiar detector authoring and reusable algorithms already exist in a security product. | A per-event Boolean rule interface is too narrow for table-producing discovery, graph algorithms, and durable model state. |
| [Tenzir packages](https://tenzir.com/docs/explanations/packages/) | Namespaced operators, complete TQL pipelines, parameters, and tests in a directory. | The strongest complete package and streaming-runtime alternative reviewed here. | Adoption adds TQL and another runtime whose state must integrate with AnalysisStore. General Python analysis needs more than its documented per-event transformation interface. |
| [Velociraptor artifacts](https://docs.velociraptor.app/docs/vql/artifacts/) and [extension guidance](https://docs.velociraptor.app/blog/2020/2020-03-07-extending-vql-plugins-7fb004cb6ec4/) | VQL artifacts that can call other artifacts. New primitive behavior uses plugins or external tools. | Installable named computations with inspectable inputs and reusable outputs. | Artifact composition alone does not add a general algorithm implementation. Adopting VQL adds another language beside existing SQL. |
| [Zeek packages](https://docs.zeek.org/projects/package-manager/en/stable/package.html) | Script packages, native plugins, or both. | One package can contain easy authoring and native algorithm code. | Zeek introduces its event and scripting runtime; native plugin loading is not an isolation boundary. |

The local references need more than pattern predicates.
[Discovery Engine](../../../../discovery-engine/src/networkpolicy/httpAggregator.go)
builds a path tree, recursively merges children, and emits generalized paths.
[Security Analytics](../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/correlation/JoinEngine.java)
combines finding time windows with category and document filters.
Araphor must support general computation over several records and datasets.
These source examples do not establish complete upstream feature parity.

## Compare complete implementation choices

| Choice | Concrete advantage | Concrete cost | Recommendation |
| --- | --- | --- | --- |
| One SDK with SQL, default Wasm, native, and optional Python targets | One model contract covers portable compiled algorithms, native dependencies, and existing queries. SDK bindings keep authoring separate from execution transport. | Araphor must qualify each advertised target and keep output, evidence, and state behavior consistent. | Selected direction; ordered work is in the 7.5 child phases. |
| Existing SQL plus native and Python models | Existing queries remain usable. Compiled algorithms run without Python; Python packages retain library compatibility. Outputs compose as datasets. | Araphor must version the native interface, isolate workers, manage dependency closures, and implement model scheduling and recovery. | Earlier candidate. Retain its native worker design as an execution target under the shared SDK. |
| Tenzir as the analysis runtime | Reuses package handling, operators, streaming windows, and statistical operations. | Introduces TQL and a C++ runtime. Araphor still needs evidence adapters and a checked checkpoint/commit integration. | Best alternative when reuse of the complete streaming runtime outweighs retention of current evaluation paths. |
| Existing SQL plus mandatory Wasm components | Restricted host imports and portable components suit Rust algorithms and bounded code. | Python dependencies need compatible builds and toolchain qualification. Ordinary native Python wheels do not become Wasm components. | Do not require every language and dependency to use Wasm. Default Wasm for compiled algorithms is compatible with separate native and Python targets. |
| DuckDB extensions as the only plugin mechanism | Native functions can run directly in query execution. | Native extensions inherit process privileges. The documented Python scalar UDF interface preserves batch cardinality and does not define model state or finding commits. | Keep reviewed engine extensions as implementation dependencies. Do not use this as the public detector installation boundary. |

DuckDB documents [Arrow Python UDFs](https://duckdb.org/docs/clients/python/function)
as array-to-array calls with equal input and output cardinality. This can help a
scalar operation; it is not the required general table-to-table interface.
DuckDB also states that [extensions share process privileges](https://duckdb.org/docs/current/operations_manual/securing_duckdb/securing_extensions).
Its SQL security guidance requires care with
[untrusted queries](https://duckdb.org/docs/current/operations_manual/securing_duckdb/overview).
Existing SQL admission restrictions must remain in force.

[Extism](https://extism.org/docs/concepts/plug-in/) supplies a reusable Wasm plugin
host and explicit imports. It does not supply detector scheduling, evidence
validation, or durable algorithm state. The current
[componentize-py documentation](https://github.com/bytecodealliance/componentize-py)
also requires imports to resolve at build time. These facts do not disqualify
Wasm, but they do not support the earlier assumption that mandatory Wasm is the
best default for familiar Python algorithm packages.

Tenzir needs a fair current comparison. Its
[2026-08-26 release](https://tenzir.com/changelog/tenzir/v6.14.0/)
adds session windows, event reordering, and statistical distribution models.
It bundles dependencies for basic Python use; container images also bundle the
interpreter. Extra Python requirements still need separate delivery. Thus,
offline installation is not a sufficient reason to reject Tenzir.
That release also states that checkpointing closes an open session. An Araphor
adapter must account for this behavior when it promises restart equivalence.
The [Python operator](https://tenzir.com/docs/reference/operators/python/) runs
once per event; parallel instances have independent interpreter state. Windows
can assemble data for analysis, and native plugins can add capabilities. The
limit is integration effort, not inability to compute a general algorithm.

## What an author writes

Use three familiar objects: a function implements an algorithm, a model produces
a named dataset, and a package distributes models, functions, and tests.
All calls and calculations stay in the model's implementation. Metadata describes identity,
types, input bindings, dependencies, and execution limits.

SQL, Wasm, native, and Python models use the same dataset catalogue. A SQL model can
select a native model's result. A native model can consume a Python model's result. Resolve
model dependencies before execution; reject cycles. Recursion inside an
algorithm does not create a cycle between model dependencies.

For example, an algorithm author can supply this ordinary Python function in
`sequence_algorithms.py`. It finds ordered event pairs within a time interval:

```python
from collections import defaultdict, deque

def ordered_pairs(events, first_kind, second_kind, max_gap_ns):
    if max_gap_ns <= 0:
        raise ValueError("max_gap_ns must be positive")
    pending = defaultdict(deque)
    for event in sorted(events, key=lambda row: (row["time_ns"], row["id"])):
        queue = pending[event["key"]]
        while queue and event["time_ns"] - queue[0]["time_ns"] > max_gap_ns:
            queue.popleft()
        if event["kind"] == second_kind:
            for previous in queue:
                if previous["time_ns"] < event["time_ns"]:
                    yield previous["id"], event["id"]
        if event["kind"] == first_kind:
            queue.append(event)
```

The input adapter supplies a checked correlation key and unique event identities.
A shared PID, IP address, or display name is not sufficient. A cross-node key
requires a qualified shared credential, object, or other identity binding.
Time order supplies correlation; it does not prove causality. Input and output
budgets bound the number of retained events and matching pairs.

A detector author imports this algorithm and chooses its predicates and result.
The following SDK is a **proposed interface**, not an installed API:

```python
from araphor import analysis
from sequence_algorithms import ordered_pairs

@analysis(
    inputs={"events": "evidence.identity_activity.v1"},
    output="example.sequence_candidates.v1",
)
def read_then_remote_use(events, max_gap_ns: int = 60_000_000_000):
    for first_id, second_id in ordered_pairs(
        events, "sensitive_read", "remote_use", max_gap_ns
    ):
        yield {"first_id": first_id, "second_id": second_id}
```

This model produces intermediate candidates. A finding model consumes them,
adds the required subject, rule code, severity, and explanation, and preserves
both evidence references. GraphAndFindingOwner validates the finding envelope.
The example does not implement a complete Hugging Face detector.

The author can replace `ordered_pairs` with a path-tree algorithm, a graph search,
or a statistical model. A Python detector can use ordinary function imports.
Models in different execution paths compose through named dataset outputs.
A [PyO3 extension](https://pyo3.rs/main/) is an optional Python binding to native
code. It is not required for native package installation or execution.

For distribution, use normal `pyproject.toml`, wheels, and
[Python entry points](https://packaging.python.org/en/latest/specifications/entry-points/)
for Python exports. The Araphor-specific entry point group identifies model
descriptors. Native and SQL exports use the same package descriptor without
Python metadata. Package building resolves and includes dependencies. Installation
does not run build hooks or fetch packages. A single local file uses a generated
descriptor and the bundled SDK. OCI can carry the completed package unchanged.

The SDK translates bounded row iteration in this example to the same typed
transport used by batch models. Bulk algorithms can consume Arrow batches
directly. This avoids making a per-event Python callback the only interface.

## Native algorithms in the same package format

Keep the public export independent of its implementation language. Its identity,
input and output schemas, parameters, evidence contract, and state version are
the caller's interface. The implementation can change from Python to native code
when compatibility tests pass. A state format change still requires conversion
or a rebuild. Record the selected binary as part of the evaluation revision.

A native-only package can have this layout. All fields are proposed:

```text
sequence/
  package.toml
  contracts/ordered-pairs.json
  native/linux-x86_64/libsequence.so
  native/linux-aarch64/libsequence.so
  tests/positive.json
  tests/unrelated-identities.json
```

```toml
name = "example/sequence"
version = "1.0.0"

[exports.ordered_pairs]
contract = "contracts/ordered-pairs.json"

[exports.ordered_pairs.native]
abi = "araphor-analysis/1"
linux-x86_64 = "native/linux-x86_64/libsequence.so"
linux-aarch64 = "native/linux-aarch64/libsequence.so"
```

Admission also checks each artifact's OS, architecture, minimum CPU features,
system-library requirements, and ABI version. A platform label alone is not a
compatibility proof. Missing compatible code produces an explicit unsupported
result. An alternative implementation must be declared, tested, and recorded;
do not silently switch to a Python implementation after a native failure.

Use a versioned C-compatible function table for native calls. SDKs hide the raw
interface from ordinary Rust or C++ algorithm code. Do not expose Rust trait
objects or compiler-specific types as the binary contract. Define ownership,
release callbacks, cancellation, errors, and state handling in that contract.
Panics and exceptions must not cross its boundary.

Use the [Arrow C Data interface](https://arrow.apache.org/docs/format/CDataInterface.html)
and [C Stream interface](https://arrow.apache.org/docs/format/CStreamInterface.html)
for batches inside a native worker. The C Data interface provides stable data
exchange and can share buffers without copies in one process. It does not define
the algorithm call interface and cannot pass process-local pointers to Control.
Use Arrow IPC across the process boundary; account for serialization and copies.

Keep workers available across evaluations within one compatible authorization
scope and dependency closure. Compatible native stages can share batches inside
one worker. Separate scopes must not share that process. An installation starts
no Python interpreter when its model dependencies are all SQL, Wasm, or native code.
Frequently used algorithms can select a qualified native target through this
same package owner; their source need not be copied from the Wasm implementation.

[Polars expression plugins](https://docs.pola.rs/user-guide/plugins/expr_plugins/)
demonstrate compiled Rust functions loaded at runtime and evaluated without
Python or GIL involvement in the expression. Borrow batch execution and the
authoring pattern; do not adopt its expression ABI as Araphor's analysis contract.
Arbitrary table cardinality, multiple inputs, checkpoints, and evidence remain
part of the Araphor contract. The worker process preserves the isolation boundary
when native package code fails. A native library is not itself a sandbox.

## State, execution, and user-visible behavior

A stateless model returns a replacement dataset for one input revision. A
stateful model additionally accepts a versioned checkpoint and returns its next
checkpoint. Module globals are temporary implementation state, not durable state.
Library functions do not create a second state store.

For late evidence, recompute the affected interval and dependent results. A
stateful algorithm must replay from a valid earlier checkpoint or rebuild from
retained input. It cannot silently subtract an event from an arbitrary learned
model. If the necessary input has expired, report incomplete coverage. An empty
successful replacement removes previous contributions from that interval.

AnalysisStore owns the checkpoint and output transaction. The host records the
package revision, input revisions, evaluation time, and any random seed. Repeat
execution must satisfy the existing retry contract. Cross-node evaluation uses
authorized retained inputs from all selected nodes; it does not rely on one
node's process memory.

Araphor ships a pinned CPython runtime and SDK when Python support is advertised.
[Python Build Standalone](https://github.com/astral-sh/python-build-standalone)
provides redistributable runtimes for this purpose. Package dependencies stay in
immutable revision-specific environments. Operators need no system Python or
runtime package downloads. Native dependencies still need compatible artifacts.

Run workers without Control credentials, database files, or network access.
Give them only their admitted package and authorized inputs. Enforce process,
memory, CPU, output, and time limits. A subprocess or Python virtual environment
alone is not a sandbox. Qualify OS isolation before accepting untrusted packages.
Never import a package into Control to inspect its decorators.

Use [Arrow IPC](https://arrow.apache.org/docs/format/Columnar.html) for bounded
table exchange with the worker. Reuse workers only within the same grant,
package revision, and dependency environment; reset transient state between
evaluations. SQL remains in the current bounded evaluator. This design limits
per-event interpreter calls but does not establish throughput or latency.

An agent uses the catalogue to inspect schemas, parameters, dependencies, tests,
coverage, and queryable results. Generate this description from the admitted
descriptor. Do not maintain a second agent-only schema. Installation uses the
same owner and grant whether a person, CLI, or agent requests it.

## Changes required in Araphor

1. Add admission and descriptors for analysis models and algorithm dependencies.
   Separate executable discovery from package trust and scope authorization.
2. Extend the current analysis owners with dependency evaluation and the managed
   worker. Reuse authorized extraction, limits, cancellation, and SQL evaluation.
   The current client query API caps output at 200 rows; do not use its display
   limit as an internal algorithm interface or silently truncate model input.
3. Replace fixed package dispatch and identifiers in
   [graph derivation](../../../../crates/araphor-data/src/graph/derive.rs) and
   [finding validation](../../../../crates/araphor-data/src/graph/model.rs).
   Keep invariant checks. Add namespaced package reason codes and typed detail
   schemas; the existing fixed reason enum is not sufficient for new detectors.
   Package output cannot create authoritative identities or prevention proof.
4. Route discovery results and policy proposals through existing validating
   owners. Keep proposal creation separate from policy activation. The current
   [discovery derivation](../../../../crates/araphor-data/src/discovery/derive.rs)
   demonstrates attribution and coverage checks that must remain mandatory.
5. Extend AnalysisStore commits for model outputs and checkpoints. Preserve
   retry, replacement, retention, recovery, and quota rules. The planned native
   graph tables support queryable results; they are not an algorithm runtime.
6. Use small Rust and platform tests for owner integration. Use package fixtures
   for algorithm behavior. Do not introduce shell test programs or worktrees.

## Acceptance cases before adoption

| Case | Required evidence |
| --- | --- |
| New local detector | Install one new model file over current evidence. Produce an expected finding without an Araphor rebuild or a new probe. |
| New reusable algorithm | Install a path-tree algorithm and two dependent models. Verify dependencies and outputs without built-in algorithm dispatch. |
| Native execution | Install and run a native graph or correlation package with Python unavailable. Verify compatible artifact selection, batch release, cancellation, and worker crash recovery. |
| Implementation replacement | Run Wasm and native implementations against the same contract fixtures; include Python if advertised. Check ordering, numeric behavior, evidence, and checkpoint compatibility before switching targets. |
| General computation | Exercise graph traversal, variable output cardinality, and a statistical dependency with native code. Record platform compatibility. |
| Cross-source correlation | Use the local Security Analytics case structure. Check unrelated identities, node differences, late input, and missing coverage. |
| Recovery | Kill a worker before commit and restart after commit. Verify output/state agreement, identical retry receipts, and replacement retractions. |
| Isolation and upgrade | Reject undeclared reads, external effects, invalid output, and incompatible state. Preserve the prior working revision on failed upgrade. |
| Hugging Face | Check each claimed observation and pre-effect guard against the existing incident acceptance. A completed detector does not prove prevention of an unobserved in-process action. |

No runtime was installed for this research. No probe, incident replay, isolation
test, or benchmark ran. The algorithm function above was checked with bounded
fixtures; the proposed SDK and lifecycle remain unimplemented. Performance and
package-size comparison require a separately approved workload and limits.
