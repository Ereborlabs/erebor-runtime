# Extensible Security Packages

Make security capabilities installable as local files, folders, or OCI artifacts.
A package can add vulnerability data, a detector, a discovery algorithm, a trace
recipe, or a policy proposal. Existing execution owners enforce approved policy.

The primary requirement is to install new algorithms and detectors over available
evidence without changes to Araphor source. Existing bpftrace scripts and SQL
queries supply collection and computation capabilities. A new detector does not
require a new trace recipe when its inputs are already available.

Status: **Design: Proposed. Implementation: Not done.** Research: 2026-10-09.
This document retains the broader design and examples. The approved
[7.5 child phases](phase-7-5-graphs-findings-and-notifications/README.md#approved-extension-and-child-phases)
own the SDK, package lifecycle, and execution work. They select default Wasm for
compiled algorithms, existing SQL, native execution, and optional Python under
one contract. Broader capabilities here remain proposed. Prevention acceptance
conditions do not change.

The later [algorithm extension evaluation](algorithm-and-detection-extension-evaluation.md)
compares the runtime choices and records the selected direction. The earlier
two-path execution recommendation below is retained as research. The child
plans supersede its mandatory Python-to-Wasm requirement.

Approved direction on 2026-10-09: evaluate Inspektor Gadget as a reusable
collection component before building an equivalent gadget loader. Adoption
and implementation remain open. Check Wasm interface compatibility separately
from OCI package compatibility.

Parent: [Control, discovery, and detection](README.md). Earlier candidate:
[Pluggable analysis artifacts](pluggable-analysis-artifacts-proposal.md).
The recommendation here resolves that candidate's open design choices for
review. The [engine contracts](engine-design.md) remain in force.

## Intended end state

An operator installs a package and selects its workload scope. Araphor checks
compatibility, permissions, required evidence, and tests. Eligible analysis
starts under the operator's existing grant. The operator sees which detectors
run, which controls are active, and which capabilities lack required inputs.

An author writes a complete computation in SQL, Python, or Rust. SQL uses the
existing query engine. Python and Rust algorithms build to WebAssembly
components for an embedded Wasmtime host. Operators install built components;
they do not manage Python environments, Java compilers, or another data service.

**Earlier recommendation:** use one typed computation contract, two execution paths
(existing SQL and Wasm), existing native enforcement owners, and optional OCI
distribution. Use standard formats at their own boundaries. Keep one package
catalogue and one AnalysisStore. Do not introduce a security query language.

Wasm and its Python toolchain are proposed additions. Their safety, dependency
support, and performance require qualification before implementation approval.
The design does not claim that every Python library can run as a component.

## Runtime flow

```text
Operator installs a folder, file, or registry reference for a selected scope
  -> package admission resolves one immutable revision and locked dependencies
  -> package admission validates types, publisher trust, limits, and imports
  -> the evaluator runs bounded data fixtures without external effects
  -> Control records the installed revision and the exact scope grant
  -> the responsible analysis owner starts supported exports under that grant
  -> policy and trace owners process requests under their own authority
  -> Araphor reports per-export readiness and per-target control activation

Accepted evidence, context, or recorded evaluation time changes
  -> the analysis owner selects authorized input revisions and prior state
  -> bounded extraction completes and durable readers close
  -> SQL or Wasm evaluates the complete computation
  -> DiscoveryOwner or GraphAndFindingOwner validates the applicable output
  -> AnalysisStore commits results, witnesses, next state, progress, and quota
  -> NotificationRouter handles the committed finding revision

An approved control reaches its execution owner
  -> the owner binds the exact target lifetime and policy revision
  -> the owner installs the supported guard before the prohibited effect
  -> the owner records activation and the observed physical result

An input is unavailable, a limit is reached, or evaluation is cancelled
  -> the owner records the failure and the affected coverage
  -> no partial result becomes a completed result
  -> temporary buffers and component instances are released
  -> an identical committed retry returns the original receipt
  -> a retry with changed inputs under the same operation key is rejected

Operator updates or rolls back a package
  -> admission checks the exact replacement and its required grants
  -> the analysis owner validates state conversion or retained-input rebuild
  -> a successful transaction changes the analysis revision for that scope
  -> policy owners track each target's separate activation result
  -> a failed preparation preserves the previous analysis revision
```

Installation cannot grant authority to itself. Existing delegated grants can
permit automatic analysis or policy activation. A package that needs additional
authority remains pending for that part. Distributed policy rollout is not a
single atomic database transaction. A control update must not remove the last
working guard before its replacement is active under the existing owner rules.

## What the research changes

Recent agent systems reinforce two useful requirements: generated code needs
restricted capabilities, and untrusted content must not become execution
authority. This applies to packages written by people and by agents. The table
separates facts from the design decisions drawn from them.

| Reference | Concrete benefit | Cost or limit | Decision for Araphor |
| --- | --- | --- | --- |
| [Inspektor Gadget](https://inspektor-gadget.io/docs/latest/gadget-devel/gadget-intro/) | An OCI artifact can contain eBPF programs, metadata, and optional Wasm processing. This is a direct precedent for portable sensor packages. | Its package format does not establish Araphor's evidence, authorization, or prevention contracts. | Evaluate collection reuse before building an equivalent loader. Keep our trace and Interceptor owners. |
| [NVIDIA OpenShell](https://docs.nvidia.com/openshell/latest/security/best-practices) | Applies filesystem, process, and network restrictions around agent execution. Provider credentials can remain outside the workload. | A sandbox changes the deployment boundary. It cannot prove protection of the unchanged Hugging Face worker. | Require explicit enforcement points. Treat mediated credentials as a separate deployment capability. |
| [CaMeL, 2025](https://arxiv.org/abs/2503.18813) | Separates trusted control flow from untrusted data and applies capability restrictions to agent actions. | Its guarantees depend on its mediated execution model. It does not observe every action inside an existing interpreter. | Keep agent output as proposed code or assessment. Owner-issued identity and permission determine authority. |
| [IronClaw Wasm tools](https://docs.ironclaw.com/capabilities/sandboxed-tools) | Shows agent tools packaged with explicit host capabilities and Wasmtime limits. | These are tool-runtime contracts, not durable detector or kernel-enforcement contracts. Product documentation is not our qualification evidence. | Borrow restricted imports and generated interfaces. Do not add an agent loop to Control. |
| [LlamaFirewall AlignmentCheck](https://meta-llama.github.io/PurpleLlama/LlamaFirewall/docs/documentation/scanners/alignment-check) | A model can inspect agent traces for departure from the task. | Inference adds latency, model dependency, and uncertain decisions. Trace access can expose sensitive data. | Accept optional external assessments through current authorized inputs. Do not make inference a default enforcement dependency. |
| [dbt Python models](https://docs.getdbt.com/docs/build/python-models) and [Hamilton functions](https://hamilton.apache.org/concepts/node/) | Named computations, explicit dependencies, tests, and inspectable intermediate results support reuse. | Neither reference supplies Araphor's physical enforcement or evidence guarantees. | Borrow these authoring properties. Do not adopt a warehouse workflow or copy either product's manifest. |
| [Tenzir packages](https://tenzir.com/docs/explanations/packages/) | Reusable TQL operators, complete pipelines, parameters, tests, and a package lifecycle form a coherent product. | Adopting it here adds TQL and another execution integration. Our owner, correction, and commit contracts still need work. | Use its package experience as a comparison target. Do not require Tenzir in the default deployment. |

Age alone does not decide suitability. OCI and SQL can serve an agent-generated
package. The additional requirement is that generation, installation, data
access, and physical authority remain separate, inspectable operations.

## Standard boundaries and new work

There is no single standard in this research that defines vulnerability data,
general algorithms, evidence, and prevention together. Use each standard for
the part it defines. The small Araphor contract connects those parts.

| Boundary | Proposed choice | What Araphor must define |
| --- | --- | --- |
| Package transport | OCI Image/Distribution 1.1 and local OCI layout | Artifact type, admitted contents, catalogue, grants, update lifecycle |
| Known vulnerable versions | [OSV records](https://ossf.github.io/osv-schema/) | Inventory mapping and qualified exposure results |
| Imported detection rules | [Sigma and its correlation specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html) | Exact field mapping and supported semantic subset; reject unsupported rules |
| Relational computation | Existing DuckDB SQL path | Authorized input views and the package result contract |
| General algorithm interface | [Wasm Component Model and WIT](https://component-model.bytecodealliance.org/design/why-component-model.html) | Versioned analysis imports, result types, quotas, and state contract |
| Tabular exchange | Bounded typed batches; Arrow IPC for Wasm table payloads | Supported types, evidence references, sensitivity, and copy limits |
| Runtime protection | Existing WorkloadProtectionPolicy and Runtime action contracts | Which package output each owner accepts and its coverage requirements |

OCI is a distribution format; it does not require a Docker daemon. ORAS
documents both registry storage and local OCI layouts. Tags are lookup names;
manifest digests identify immutable content. [OCI artifact model](https://oras.land/docs/concepts/artifact/).

Use the planned [registry and trust owner](../../daemon-client/phase-10-oci-registry-trust-hub-and-packaging.md).
That work is deferred and not implemented. Extend its scope for analysis
artifacts through an explicit design decision; its current restrictions on
executable adapters do not already authorize algorithm plugins. Keep one
credential store, trust policy, download cache, and garbage collector. Content
digests required by OCI do not justify new analysis bookkeeping digests.

Local folders and OCI artifacts use the same admission path. Pin dependencies
and retain their licences and provenance. No install hooks, automatic `pip`
execution, or runtime source downloads run on Control or Node. A publisher
signature establishes origin, not correctness or permission. Registry access
is optional; offline imports include all required content and trust material.

The same package interface can serve Linux, Kubernetes, terminal, browser, and
API evidence. Each surface needs a qualified input adapter and, for prevention,
an execution path controlled by its enforcement owner. A new data adapter must
preserve source authentication, attribution, and coverage. An analysis component
does not gain arbitrary network access to become a connector. Unsupported
surfaces remain visible requirements; a shared package format cannot create
missing hooks or prevent actions outside the controlled path.

## Inspektor Gadget collection evaluation

The [source evaluation against existing bpftrace](inspektor-gadget-evaluation.md)
is complete for release `v0.56.0`. It recommends retaining bpftrace. This
collection evaluation does not resolve algorithm or detector extension.
Changes to trace admission are not a prerequisite for the computation contract.
Do not add an equivalent custom gadget loader
or Inspektor Gadget by default for this proposal. Reconsider an optional
Inspektor Gadget adapter for a named native sensor with a demonstrated benefit.
Runtime integration remains unqualified. The criteria below apply to that
possible future adapter.

Evaluate Inspektor Gadget for gadget loading, probe lifecycle, enrichment, and
collection. Keep policy authority, authenticated evidence intake, durable
analysis, and finding validation under their current owners. Existing bpftrace
capture and Interceptor enforcement remain the baseline for this evaluation.

The first documentation check found separate contracts. Inspektor Gadget's
[Wasm API](https://inspektor-gadget.io/docs/latest/gadget-devel/gadget-wasm-api-raw/)
uses imports from `ig`, gadget lifecycle exports, and data-source callbacks.
It also exposes BPF map creation and update operations. The proposed analysis
interface uses typed components with authorized input snapshots and explicit
result/state commits. An OCI artifact can carry either binary; that does not
make the binary valid for both hosts. Keep collector processing in its qualified
host. Any reuse of algorithm code needs an explicit port or checked adapter.

The [published APIs](https://inspektor-gadget.io/docs/latest/apis/) include Go
embedding and gRPC. Compare these integration paths against Araphor's Rust
owners and self-contained installation. Evaluate a supervised local collector
before introducing a separately operated service. The gRPC documentation is
incomplete; inspect the protocol and source at a pinned release before choosing
an integration. Do not treat the documentation review as a runtime result.

| Evaluation item | Required result before adoption |
| --- | --- |
| Installation and trust | A pinned release and gadget digest work through the planned package admission path, including offline use. One authority decides publisher trust and allowed gadgets. |
| Scope and identity | Capture obeys the exact authorized target lifetime. Tests cover target replacement and PID/namespace reuse. Enriched names alone do not become authoritative graph identities. |
| Evidence and loss | An adapter preserves source identity, schema, timestamps, and available loss signals. Missing attribution or coverage remains explicit; an empty stream does not prove no activity. |
| Lifecycle and privilege | Cancellation, timeout, crash, and restart release probes and owned resources. Collector privileges cannot change enforcement policy or bypass capture grants. |
| Wasm interface | A small gadget exercises imports, callbacks, data types, memory ownership, and cleanup. Compare these with the analysis contract. Record required adaptations and unsupported capabilities. |
| Deployment and resources | State the added binaries, privileges, runtime dependencies, and licence obligations. Functional checks establish bounded failure behavior. Performance measurements require separate authorization. |

Use a finite file-open capture with one selected workload and one unrelated
workload as the first functional case. Include a denied open, an allowed open,
target replacement, cancellation, and collector failure. The existing native
guard supplies the denial. Compare collector output with production evidence
without attributing that prevention to the collector. Follow the existing
lightweight-then-physical qualification order.

Record the result as reuse without upstream changes, reuse with a bounded
adapter, or reject for a named unmet requirement. Require this result before
building an equivalent custom loader. A rejection does not authorize a new
loader or a replacement enforcement path by itself.

## One computation contract

A computation has named typed inputs, typed parameters, named typed outputs,
and an optional versioned state type. Its complete body contains its filters,
joins, grouping, windows, and algorithm. The manifest contains identity,
references, requirements, and limits. It contains no second calculation.

```text
evaluate(authorized input snapshots, parameters, prior state, recorded time)
  -> output tables, next state, evidence references
```

Input types include authoritative subject keys and lifetimes, source positions,
coverage, and sensitivity. A PID, path, display name, or timestamp alone is not
a subject identity. Computations can return intermediate tables, finding
candidates, profile candidates, or policy proposals. Return types select the
existing validating owner. A component cannot write directly to an owner store.

Current graph validation accepts a fixed set of package identifiers in
[`graph/model.rs`](../../../../crates/araphor-data/src/graph/model.rs).
The detector implementations are built into
[`graph/derive.rs`](../../../../crates/araphor-data/src/graph/derive.rs).
These owners need an admitted computation interface for new algorithms and
detectors. The fixed trace recipe set is a separate admission restriction;
it is not a limit of the bpftrace language or the primary gap in this proposal.

Each export defines its interface once. SQL exports use a typed sidecar
contract. Component exports use generated bindings and a compiled descriptor.
The build checks that the descriptor matches the executable interface. CLI
help, JSON inspection, console forms, and agent tools use that same descriptor.
Do not maintain a separate prompt schema for agents.

An input binding can reference a versioned source dataset or another export.
Bindings describe dependencies, not calculations. Admission resolves a finite
dependency graph and rejects cycles and undeclared dynamic imports. SQL sees
its inputs as read-only views. Code receives the same inputs as table handles.
The scheduler can share identical intermediate results only within compatible
authorization, sensitivity, parameters, and input revisions.

Recursive graph or directory algorithms run inside a computation. Recursion
does not require a cycle between packages. Evidence-qualified causal graphs
remain different from the dependency graph used to schedule computations.

## Example: install a detector

All `araphor package` commands, package fields, dataset names, and SDK bindings
below are **proposed interfaces**. They are not commands available today.
The SQL and Python bodies illustrate complete computations.

```text
read-attempts/
  package.toml
  models/read_attempts.sql
  contracts/read_attempts.json
  tests/positive.json
  tests/benign.json
  tests/missing-coverage.json
```

```toml
schema = 1
name = "example/read-attempts"
version = "1.0.0"

[exports.read_attempts]
entry = "models/read_attempts.sql"
contract = "contracts/read_attempts.json"
```

The contract declares input `events` of type `file-access.v1`, parameter
`as_of` of type timestamp, and output `candidates` of type
`repeated-access-candidate.v1`. Input binding and tenant scope come from the
installation. The body defines the five-minute interval and threshold once:

```sql
SELECT subject_id,
       count(*) AS denied_reads,
       list(event_ref ORDER BY event_ref) AS evidence_refs
FROM events
WHERE operation = 'OpenRead'
  AND decision = 'Deny'
  AND event_time >= CAST($as_of AS TIMESTAMP) - INTERVAL '5 minutes'
  AND event_time < CAST($as_of AS TIMESTAMP)
GROUP BY subject_id
HAVING count(*) >= 3
```

The proposed input view has one row per accepted event reference. `subject_id`
resolves to the full owner-qualified identity in the authorized snapshot.
`as_of` is bound as a value and recorded for replay. The owner records the
input snapshot's actual coverage. It reevaluates time-dependent exports on
recorded clock ticks, including ticks with no new events. The query adapter
must establish the required interval for this supported query shape before it
can certify a complete evaluation. It must not infer completeness from returned
rows or assume it can infer every arbitrary program's data requirements.

Three denied reads produce one candidate with three witnesses. Two produce no
candidate. Missing source coverage produces an incomplete evaluation; it does
not prove absence. Repeated denials can have a benign cause. This detector
reports behavior for review and does not claim that every match is an attack.

```text
araphor package test ./read-attempts
araphor package install ./read-attempts --scope namespace/model-workers
araphor package inspect example/read-attempts --json
```

With existing read permission and complete compatible input, installation
starts this detector. A single SQL file with a standard input/output contract
can use a built-in template; a custom contract needs its sidecar. A standalone
OSV or supported Sigma file can use its format adapter. Format detection must
reject ambiguous files. None of these shortcuts changes admission rules.

The same package can come from an OCI registry:

```text
araphor package install oci://registry.example.org/security/read-attempts:1.0.0 --scope namespace/model-workers
```

Admission resolves the tag once and records the verified manifest digest in
the installation receipt. Later registry tag changes do not change that
installed revision. This reference is an example, not a published package.

## Example: add a new algorithm in Python

An author can add an algorithm that is awkward to express in SQL. This function
calculates a median and median absolute deviation. It returns no result for an
empty or invalid sample; it does not turn missing data into a zero baseline.

```python
from math import isfinite
from statistics import median

def baseline(values: list[float]) -> tuple[float, float] | None:
    if not values or not all(isfinite(value) for value in values):
        return None
    center = median(values)
    deviation = median(abs(value - center) for value in values)
    return (center, deviation) if isfinite(center) and isfinite(deviation) else None
```

Input `[90, 100, 110]` returns `(100, 10)`. Input `[100, 100, 100]` returns
`(100, 0)`; a consumer must define its zero-deviation rule before division.
This is a reusable algorithm, not a complete anomaly detector.

The proposed build command generates the component wrapper from the typed
export, checks the contract, runs fixtures, and packages the compiled result:

```text
araphor package build ./robust-baseline
araphor package install ./robust-baseline/dist --scope namespace/model-workers
```

Another export can consume this result as an input table, then join it with
current measurements. A Rust implementation can replace the Python body under
the same contract and fixtures. Whole-table algorithms can read bounded batches
and return several tables plus state; the interface is not limited to scalar
UDFs or calls for each event.

[componentize-py](https://github.com/bytecodealliance/componentize-py) provides
the Python-to-component toolchain. It currently requires imports to resolve
at build time. The author needs a qualified build environment; the operator
receives the component. Python retains interpreter and artifact-size costs.
Native Python extensions, GPU libraries, and arbitrary PyPI packages are not
promised. Reject unsupported dependencies during build. Do not silently fall
back to running Python inside Control.

## Example: discovery and correlation from the local repositories

The local [discovery algorithm](../../../../discovery-engine/src/common/pathAggregator.go)
uses a directory tree and collapses a node when its child count exceeds three.
An equivalent package can consume observed paths and return generalized path
candidates. Its fixtures must preserve the recursive behavior, path rules, and
threshold boundary. Four children can produce a directory candidate; three do
not trigger that collapse. A candidate to allow `/models/` grants more access
than the observed four files. DiscoveryOwner must retain that expansion for
policy review; observation never grants permission by itself.

The local [JoinEngine](../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/correlation/JoinEngine.java)
uses inclusive time searches on both sides of a finding. For that path, an
equivalent join uses `other_time BETWEEN anchor_time - window AND anchor_time
+ window`, with the applicable rule/tag conditions. It is not automatically an
ordered attack sequence. Package fixtures must test both time boundaries,
reversed arrival, unrelated identities, and corrected findings.

These are distinct computations under one interface. A directory algorithm can
use Wasm; a bounded correlation can use SQL. Neither requires a new manifest
operator or a second storage engine. This is an extension path for the inspected
algorithms, not a claim of complete parity with both repositories.

## Example: add tracing and known vulnerability data

A package can include the existing syscall-error recipe:

```bpftrace
tracepoint:raw_syscalls:sys_exit
/cgroup == $1 && args.ret < 0/
{
  @errors[args.id, args.ret] = count();
}
interval:s:1 { print(@errors); }
```

TraceOwner resolves the selected target and grants a finite capture. Node
rechecks the lifetime; Interceptor supervises the real bpftrace process. These
are cumulative counters. A consumer must not add successive snapshots as if
they were interval deltas. The recipe supplies diagnosis, not a blocking hook.
See the [current trace contract](../../araphor-observability/README.md).

Current source recognizes a fixed recipe set. New source needs a reviewed
recipe contract for hooks, attribution, decoding, sensitivity, and limits.
A cgroup predicate does not confine arbitrary bpftrace source. An OCI signature
does not make a new probe safe. A package cannot install a new kernel enforcement
primitive; that requires qualified Interceptor development.

For known vulnerabilities, put OSV records in `advisories/` and bind an inventory
input. For a fictional package affected from version `1.0.0` until the fix at
`1.2.3`, the importer reports an exposure candidate for installed `1.2.2` and
none for `1.2.3`, subject to the ecosystem's version rules. Unknown inventory
remains unknown. This installs vulnerability knowledge. Evidence of a vulnerable
version alone does not prove exploitation or activate a blocking policy.

## Example: a Hugging Face protection package

The [published incident timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
includes an HDF5 external-file read, execution inside an existing Python worker,
credential use, infrastructure pivots, and output through permitted services.
These require several controls and evidence sources, not one process rule.

```text
hugging-face-worker/
  package.toml
  models/credential_access.sql
  models/cross_node_chain.sql
  policies/worker-files.yaml
  traces/failed-opens.bt
  tests/attack.json
  tests/benign.json
  tests/missing-provider-evidence.json
```

`worker-files.yaml` uses the existing WorkloadProtectionPolicy schema. A file
rule has the following existing shape; this is only the rule fragment, not a
complete deployable policy. The target below is the current protected-file
fixture, not a claim that this path alone protects the incident workload.

```yaml
name: secret-read
path: /tmp/mithril-observe-secret
recursive: false
exact: true
operations: [OpenRead]
action: Deny
```

| Attack step | What the package can request | What proves prevention, or limits it |
| --- | --- | --- |
| Read a protected file through a data parser | Existing file guard bound to the correct subject and object | The prohibited read yields no bytes, while the paired allowed read succeeds. HDF5 and alias cases need their own physical tests. |
| Execute code within an existing worker | Correlate later file, network, or API effects | There may be no new process or exec event. Guard the first distinguishable prohibited effect. Do not invent an exec edge. |
| Use a credential already in memory | Restrict a distinguishable subsequent effect | A file hook cannot revoke bytes already in memory. Job-specific intent may be unobservable in a shared interpreter. |
| Change cluster or cloud resources | Native controls where applicable; authorized API mediation or provider controls where deployed | Audit logs can prove a past action. Admission does not block a Kubernetes Secret GET. Each claimed guard needs a pre-effect route and physical proof. |
| Continue on another node | Join authoritative audit/object/pod/binding identities with remote evidence | Time proximity, shared names, or an IP address alone do not prove the causal chain. |
| Send data through an allowed service | Operation/resource restrictions on a governed API path | A destination allowlist alone cannot distinguish all permitted-service abuse, especially inside opaque TLS. |

An installation should return a result such as this, with target-specific
evidence links behind each line:

```text
Installed: example/hugging-face-worker@1.0.0
Protected-file guard: active on 2 of 2 selected targets
Credential-access analysis: running
Cross-node analysis: waiting for Kubernetes audit input
Provider API protection: unavailable; request path is not governed
```

Do not label the whole workload protected from all incident paths. The current
[physical result](phase-7-5-graphs-findings-and-notifications/README.md) proves one
protected open denial and a benign read. It explicitly excludes full HDF5,
Jinja, provider, cloud, and cross-node qualification.

The [unchanged-workload acceptance](../hugging-face-adversarial-acceptance.md)
keeps the same image, credentials, RBAC, network, and shared interpreter.
Removing credentials, splitting jobs, or inserting an API wrapper can improve
another deployment profile. It cannot substitute for this acceptance case.
Where the baseline has no distinguishable pre-effect signal, report that gap.

## Agents, permissions, and evidence

An agent can inspect schemas, read authorized evidence, write a package, run
fixtures, compare results, and propose installation or policy changes. A single
machine-readable catalogue exposes contracts, examples, input requirements,
diagnostics, and result references. The CLI and any agent adapter call the same
owner APIs. Package descriptions and retrieved evidence remain untrusted data.

For example, an agent can read a finding's witnesses, create a stricter file
policy proposal, and replay attack and benign fixtures. The policy owner then
checks the exact target, current revisions, and approval or delegated grant.
An agent-written explanation cannot supply missing evidence or approve itself.
No external model receives tenant data without the applicable data permission.

Computation outputs retain the input sensitivity. Declaring an aggregate does
not automatically declassify its source. Logs, errors, intermediate tables,
and cached results need the same authorization checks as final outputs.
Finding validation checks witness existence and authority. It does not prove
that an arbitrary author's algorithm is sound; tests and publisher trust remain
separate from physical enforcement proof.

## Execution, recovery, and performance

The default evaluator recomputes a complete bounded result. It replaces that
result for its exact source window. Later versions can add explicit incremental
update functions, but they must match recomputation for additions, removals,
and corrections. Persistent guest memory is not the recovery mechanism.

Keep state in AnalysisStore under tenant, installed revision, scope, export,
and partition. Store its format version and input progress with its results.
Define event time, arrival time, clock uncertainty, and interval boundaries in
the computation contract. Missing history cannot produce a certified absence.
Recorded evaluation time drives windows and expiry; ambient guest clocks do not.

Preserve whole-version authorization and the existing finding selection rule:
latest version per source window, then latest finding across selected windows.
A replacement window stops contributing removed findings. Historical evidence
remains referenceable. A corrected finding does not undo an executed response.

Reuse the [native graph row TODOs](phase-7-5-graphs-findings-and-notifications/README.md#native-graph-storage-improvement-todos)
inside AnalysisStore. Keep one authoritative graph representation and feed the
existing VTab. Typed rows also let authorized agents join subjects, relationships,
and findings. Package support does not need a second graph store.

SQL executes through current admission and extraction controls. No package SQL
can enable filesystem access, network access, extension loading, or arbitrary
native UDFs. Wasm receives only admitted table handles, parameters, recorded
context, and bounded output/state functions. Link no ambient filesystem,
network, process, credential, or policy-write capability.

Use Wasmtime memory and execution limits plus host-side budgets for input,
output, state, compilation, stack, buffers, and total concurrent work. Fuel and
epochs do not interrupt a blocked host call; host functions need bounded work
and cancellation too. [Wasmtime interruption contract](https://docs.wasmtime.dev/api/wasmtime/struct.Config.html#method.epoch_interruption).
Reject imported capabilities outside the analysis interface. Treat compilation
caches as host-owned executable material; do not deserialize untrusted native
cache files supplied in a package.

Keep native SQL scans, filters, and joins in the existing engine. Cross into
Wasm with bounded batches for the algorithm that needs it. Arrow IPC does not
make the guest boundary zero-copy. Cache validated components and prepared
queries; instantiate isolated evaluation state. Bound queues, dependency fanout,
partition count, retained witnesses, and cumulative state. A detector that falls
behind reports stale coverage and cannot stall evidence intake.

These choices aim to limit overhead; no performance result is claimed. Compare
startup time, package size, memory, input/output copying, cancellation, and
sustained mixed-query load before release. Performance tests require separate
authorization under the repository verification rules.

## Why these choices, and when to change them

| Decision | Benefit for this product | Cost and condition for reconsideration |
| --- | --- | --- |
| Existing SQL plus Wasm components | Reuses current queries and permits new general algorithms without a new language or operator-managed runtime. | Two evaluators need one semantic contract and parity tests. Python components can be large or slow. Reconsider the guest path if representative algorithms fail qualification. |
| Components rather than unrestricted CPython in Control | Explicit imports, bounded execution, and portable installation. | Reduced Python library compatibility. A separate Python worker offers more libraries but adds process isolation, environment, and recovery work; it is not the default fallback. |
| Components rather than native shared-library plugins | A plugin cannot directly call arbitrary host APIs through a native ABI. | Host bindings and serialization cost work. A measured hot path can become a reviewed built-in through normal release qualification. |
| Optional OCI rather than a custom package server | Existing registries, immutable references, offline layouts, and attached trust material. | Registry credentials, trust, cache, and revocation still need implementation. Local admission must work without a registry. |
| Existing DuckDB rather than adopting Tenzir as the core | Preserves the self-contained deployment, storage owner, and current SQL surface. | We must implement package lifecycle and computation contracts. Tenzir becomes stronger if complete TQL pipelines and its integrations outweigh this integration cost. |
| Bounded recomputation before DBSP/Differential | Straightforward correction and replay semantics under the current owner. | Large windows can be expensive. [DBSP](https://docs.rs/dbsp/latest/dbsp/) or Differential becomes relevant when measured recomputation cost justifies an incremental runtime and its recovery integration. |
| SQL and code before a mandatory PRQL frontend | Operators install the same package regardless of author language. | [PRQL](https://prql-lang.org/book/) can improve relational authoring but does not supply general algorithms or prevention. A qualified build-time compiler can emit SQL later without changing installation. |

## Required work before implementation

The following items are design TODOs, not completed implementation:

Keep existing collection as the input baseline. The
[completed source evaluation](inspektor-gadget-evaluation.md) does not make
trace recipe extension a prerequisite. The first acceptance case must install
a new algorithm and a detector that uses it over available evidence, without
a new probe or a change to Araphor source.

1. Define the package descriptor, typed table contract, exact failure states,
   and WIT imports. Map each change to existing Control, data, trace, and
   execution owners. Keep admission shared across files, folders, and OCI.
2. Replace fixed graph package dispatch with admitted export dispatch while
   preserving GraphAndFindingOwner validation. Reuse DiscoveryOwner for profile
   and proposal output. QueryOwner must not become the package scheduler.
3. Qualify SQL and Rust/Python component examples against the same inputs,
   correction cases, authorization, cancellation, and recovery contract.
   Include recursive path aggregation and cross-source correlation.
4. Extend the existing distribution plan for analysis artifacts. Define
   dependency updates, revocation, uninstall, and offline trust. Uninstall stops
   analysis and closes traces; policy removal uses its owner and does not erase
   historical findings or silently remove protection.
5. Add focused Rust and platform tests through production APIs. Cover malicious
   imports, forged witnesses, changed retries, state conversion failure, reopen,
   backup/restore, absent data, late evidence, and time-driven expiry. Package
   fixtures are bounded data tests; install does not execute attack scenarios.
6. Add paired lightweight and physical incident cases in `mithril-e2e`. Preserve
   the unchanged workload and test benign use beside each claimed denial.
   Physical attack tests run only in the authorized qualification environment.

Reuse current owners in focused modules. Share contract validation, encoding,
and evaluation between admission, execution, and fixture tests. Do not create
large shell test programs, linked worktrees, a second store, or a new service
to implement this proposal.

## Research and verification record

Reviewed the linked primary documentation and local graph, query, discovery,
trace, policy-fixture, distribution-plan, and qualification sources. Upstream
product capabilities above are documentation findings, not local test results.
The algorithm examples do not assert complete upstream feature parity.

Inspektor Gadget evaluation: documentation and release-pinned source review
are complete. The recommendation retains bpftrace as the default and limits
Inspektor Gadget to a possible adapter for a specific future requirement.
Adapter execution, lifecycle tests, and deployment qualification are **Not done**.

Document verification on 2026-10-09: local Markdown targets and code fences
passed; the TOML example parsed; the Python function passed normal, constant,
empty, invalid-number, even-sample, and overflow cases. Whitespace checks passed.
The SQL body was not executed: no DuckDB CLI or Python module was available.
The proposed package commands were not run. Implementation, Wasm toolchain
qualification, benchmarks, and full incident prevention are **Not done**.
